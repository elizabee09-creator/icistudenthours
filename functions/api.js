const SUPABASE_URL = env => env.SUPABASE_URL;
const SERVICE_KEY = env => env.SUPABASE_SERVICE_ROLE_KEY;
const SESSION_SECRET = env => env.APP_SESSION_SECRET;
const INITIAL_ADMIN_PASSWORD = env => env.INITIAL_ADMIN_PASSWORD;

const enc = new TextEncoder();

function json(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      "Cache-Control": "no-store",
      ...headers
    }
  });
}

function b64url(bytes) {
  let str = "";
  bytes.forEach(b => str += String.fromCharCode(b));
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

function b64urlText(text) {
  return b64url(enc.encode(text));
}

function decodeB64url(value) {
  value = value.replace(/-/g, "+").replace(/_/g, "/");
  while (value.length % 4) value += "=";
  return atob(value);
}

async function hmac(secret, value) {
  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );

  return new Uint8Array(
    await crypto.subtle.sign("HMAC", key, enc.encode(value))
  );
}

async function signSession(payload, env) {
  const body = b64urlText(JSON.stringify(payload));
  const sig = b64url(await hmac(SESSION_SECRET(env), body));
  return `${body}.${sig}`;
}

async function readSession(request, env) {
  try {
    const cookie = request.headers.get("Cookie") || "";
    const match = cookie.match(/(?:^|;\s*)club_session=([^;]+)/);
    if (!match) return null;

    const [body, sig] = match[1].split(".");
    if (!body || !sig) return null;

    const expected = b64url(await hmac(SESSION_SECRET(env), body));
    if (sig !== expected) return null;

    const payload = JSON.parse(decodeB64url(body));

    if (!payload.exp || Date.now() > payload.exp) return null;

    return payload;
  } catch {
    return null;
  }
}

function sessionCookie(token, expired = false) {
  return `club_session=${expired ? "" : token}; Path=/; HttpOnly; SameSite=Lax; Secure; Max-Age=${expired ? 0 : 28800}`;
}

function bytesToHex(bytes) {
  return Array.from(bytes)
    .map(b => b.toString(16).padStart(2, "0"))
    .join("");
}

function hexToBytes(hex) {
  const out = new Uint8Array(hex.length / 2);

  for (let i = 0; i < out.length; i++) {
    out[i] = parseInt(hex.substr(i * 2, 2), 16);
  }

  return out;
}

async function hashPassword(password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iterations = 160000;

  const key = await crypto.subtle.importKey(
    "raw",
    enc.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );

  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt,
      iterations,
      hash: "SHA-256"
    },
    key,
    256
  );

  return `pbkdf2$${iterations}$${bytesToHex(salt)}$${bytesToHex(new Uint8Array(bits))}`;
}

async function verifyPassword(password, stored) {
  try {
    const [kind, iterationText, saltHex, hashHex] = stored.split("$");

    if (kind !== "pbkdf2") return false;

    const iterations = Number(iterationText);
    const salt = hexToBytes(saltHex);

    const key = await crypto.subtle.importKey(
      "raw",
      enc.encode(password),
      "PBKDF2",
      false,
      ["deriveBits"]
    );

    const bits = await crypto.subtle.deriveBits(
      {
        name: "PBKDF2",
        salt,
        iterations,
        hash: "SHA-256"
      },
      key,
      256
    );

    return bytesToHex(new Uint8Array(bits)) === hashHex;
  } catch {
    return false;
  }
}

function normalize(value) {
  return String(value || "")
    .trim()
    .toLowerCase()
    .replace(/\s+/g, " ");
}

async function db(path, env, options = {}) {
  if (!SUPABASE_URL(env) || !SERVICE_KEY(env)) {
    throw new Error("Database environment variables are missing.");
  }

  const response = await fetch(
    `${SUPABASE_URL(env)}/rest/v1/${path}`,
    {
      method: options.method || "GET",

      headers: {
        apikey: SERVICE_KEY(env),
        Authorization: `Bearer ${SERVICE_KEY(env)}`,
        "Content-Type": "application/json",
        Prefer: options.prefer || "return=representation"
      },

      body: options.body
        ? JSON.stringify(options.body)
        : undefined
    }
  );

  const text = await response.text();

  let value = null;

  try {
    value = text ? JSON.parse(text) : null;
  } catch {
    value = text;
  }

  if (!response.ok) {
    throw new Error(
      typeof value === "object"
        ? value.message || value.error || "Database error"
        : "Database error"
    );
  }

  return value;
}

async function allUsers(env) {
  return await db(
    "club_users?select=id,first_name,last_name,role,is_admin,password_hash&order=last_name.asc,first_name.asc",
    env
  );
}

async function publicUserById(id, env) {
  const rows = await db(
    `club_users?id=eq.${encodeURIComponent(id)}&select=id,first_name,last_name,role,is_admin`,
    env
  );

  return rows?.[0] || null;
}

function publicUser(user) {
  return {
    id: user.id,
    firstName: user.first_name,
    lastName: user.last_name,
    name: `${user.first_name} ${user.last_name}`,
    role: user.role,
    isAdmin: !!user.is_admin
  };
}

async function requireUser(request, env) {
  const session = await readSession(request, env);

  if (!session) {
    const error = new Error("Please sign in.");
    error.status = 401;
    throw error;
  }

  const user = await publicUserById(session.uid, env);

  if (!user) {
    const error = new Error("Account not found.");
    error.status = 401;
    throw error;
  }

  return publicUser(user);
}

function requireTeacher(user) {
  if (user.role !== "teacher") {
    const error = new Error("Teacher access required.");
    error.status = 403;
    throw error;
  }
}

export async function onRequest(context) {
  const { request, env } = context;

  try {
    if (!SESSION_SECRET(env)) {
      return json({ error: "APP_SESSION_SECRET is missing." }, 500);
    }

    const url = new URL(request.url);
    const action = url.searchParams.get("action") || "";

    let body = {};

    if (request.method !== "GET") {
      try {
        body = await request.json();
      } catch {}
    }

    if (action === "login" && request.method === "POST") {

      const firstName = String(body.firstName || "").trim();
      const lastName = String(body.lastName || "").trim();
      const password = String(body.password || "").trim();

      if (!firstName || !lastName || !password) {
        return json(
          { error: "Enter first name, last name, and password." },
          400
        );
      }

      let users = await allUsers(env);

      if (
        users.length === 0 &&
        normalize(firstName) === "elizabeth" &&
        normalize(lastName) === "walters"
      ) {

        if (
          !INITIAL_ADMIN_PASSWORD(env) ||
          password !== INITIAL_ADMIN_PASSWORD(env)
        ) {
          return json(
            {
              error:
                "Administrator account has not been initialized with this password."
            },
            401
          );
        }

        const admin = {
          id: crypto.randomUUID(),
          first_name: "Elizabeth",
          last_name: "Walters",
          role: "teacher",
          is_admin: true,
          password_hash: await hashPassword(password)
        };

        const created = await db(
          "club_users",
          env,
          {
            method: "POST",
            body: admin
          }
        );

        users = created;
      }

      const found = users.find(
        user =>
          normalize(user.first_name) === normalize(firstName) &&
          normalize(user.last_name) === normalize(lastName)
      );

      if (!found) {
        return json(
          {
            error:
              "No account was found with that first and last name."
          },
          401
        );
      }

      if (!(await verifyPassword(password, found.password_hash))) {
        return json(
          {
            error:
              `The password does not match the account for ${found.first_name} ${found.last_name}.`
          },
          401
        );
      }

      const user = publicUser(found);

      const token = await signSession(
        {
          uid: user.id,
          role: user.role,
          exp: Date.now() + 8 * 60 * 60 * 1000
        },
        env
      );

      return json(
        { user },
        200,
        {
          "Set-Cookie": sessionCookie(token)
        }
      );
    }

    if (action === "logout" && request.method === "POST") {
      return json(
        { ok: true },
        200,
        {
          "Set-Cookie": sessionCookie("", true)
        }
      );
    }

    if (action === "me") {

      const session = await readSession(request, env);

      if (!session) {
        return json({ user: null });
      }

      const user = await publicUserById(session.uid, env);

      return json({
        user: user ? publicUser(user) : null
      });
    }

    const me = await requireUser(request, env);

    if (action === "data") {

      if (me.role === "student") {

        const hours = await db(
          `club_hours?student_id=eq.${encodeURIComponent(me.id)}&select=id,student_id,club,work_date,hours,note,entered_by_name&order=work_date.desc`,
          env
        );

        return json({
          users: [me],

          entries: (hours || []).map(entry => ({
            id: entry.id,
            studentId: entry.student_id,
            club: entry.club,
            date: entry.work_date,
            hours: Number(entry.hours),
            note: entry.note || "",
            enteredBy: entry.entered_by_name || ""
          }))
        });
      }

      requireTeacher(me);

      const users = (await allUsers(env)).map(publicUser);

      const hours = await db(
        "club_hours?select=id,student_id,club,work_date,hours,note,entered_by_name&order=work_date.desc",
        env
      );

      return json({
        users,

        entries: (hours || []).map(entry => ({
          id: entry.id,
          studentId: entry.student_id,
          club: entry.club,
          date: entry.work_date,
          hours: Number(entry.hours),
          note: entry.note || "",
          enteredBy: entry.entered_by_name || ""
        }))
      });
    }

    if (action === "saveUser" && request.method === "POST") {

      requireTeacher(me);

      const id = body.id || null;
      const firstName = String(body.firstName || "").trim();
      const lastName = String(body.lastName || "").trim();
      const role =
        body.role === "teacher"
          ? "teacher"
          : "student";

      const password =
        body.password
          ? String(body.password)
          : null;

      if (!firstName || !lastName) {
        return json(
          { error: "First and last name are required." },
          400
        );
      }

      const users = await allUsers(env);

      const duplicate = users.find(
        user =>
          user.id !== id &&
          normalize(user.first_name) === normalize(firstName) &&
          normalize(user.last_name) === normalize(lastName)
      );

      if (duplicate) {
        return json(
          { error: "That person is already in the system." },
          409
        );
      }

      if (id) {

        const existing = users.find(user => user.id === id);

        if (!existing) {
          return json(
            { error: "Account not found." },
            404
          );
        }

        if (existing.is_admin && !me.isAdmin) {
          return json(
            {
              error:
                "The administrator account is protected."
            },
            403
          );
        }

        const update = {
          first_name: firstName,
          last_name: lastName,
          role: existing.is_admin
            ? "teacher"
            : role,
          is_admin: !!existing.is_admin
        };

        if (password) {
          update.password_hash =
            await hashPassword(password);
        }

        await db(
          `club_users?id=eq.${encodeURIComponent(id)}`,
          env,
          {
            method: "PATCH",
            body: update
          }
        );

        return json({ ok: true });
      }

      if (!password) {
        return json(
          {
            error:
              "A password is required for a new account."
          },
          400
        );
      }

      await db(
        "club_users",
        env,
        {
          method: "POST",

          body: {
            id: crypto.randomUUID(),
            first_name: firstName,
            last_name: lastName,
            role,
            is_admin: false,
            password_hash:
              await hashPassword(password)
          }
        }
      );

      return json({ ok: true });
    }

    if (
      action === "deleteUser" &&
      request.method === "POST"
    ) {

      requireTeacher(me);

      if (!me.isAdmin) {
        return json(
          {
            error:
              "Only Elizabeth Walters can delete accounts."
          },
          403
        );
      }

      const id = String(body.id || "");

      if (!id) {
        return json(
          { error: "User ID is required." },
          400
        );
      }

      if (id === me.id) {
        return json(
          {
            error:
              "You cannot delete the account you are currently using."
          },
          400
        );
      }

      const users = await allUsers(env);

      const target =
        users.find(user => user.id === id);

      if (!target) {
        return json(
          { error: "Account not found." },
          404
        );
      }

      if (target.is_admin) {
        return json(
          {
            error:
              "The protected administrator account cannot be deleted."
          },
          403
        );
      }

      await db(
        `club_users?id=eq.${encodeURIComponent(id)}`,
        env,
        {
          method: "DELETE",
          prefer: "return=minimal"
        }
      );

      return json({ ok: true });
    }

    if (
      action === "saveEntry" &&
      request.method === "POST"
    ) {

      requireTeacher(me);

      const id = body.id || null;
      const studentId =
        String(body.studentId || "");

      const club =
        String(body.club || "");

      const date =
        String(body.date || "");

      const hours =
        Number(body.hours);

      const note =
        String(body.note || "").trim();

      if (
        !studentId ||
        ![
          "BBQ Club",
          "Bread Club",
          "Garden Club",
          "Events"
        ].includes(club) ||
        !date ||
        !Number.isFinite(hours) ||
        hours <= 0
      ) {

        return json(
          {
            error:
              "Student, club, date, and valid hours are required."
          },
          400
        );
      }

      const payload = {
        student_id: studentId,
        club,
        work_date: date,
        hours,
        note,
        entered_by: me.id,
        entered_by_name: me.name
      };

      if (id) {

        await db(
          `club_hours?id=eq.${encodeURIComponent(id)}`,
          env,
          {
            method: "PATCH",
            body: payload
          }
        );

      } else {

        await db(
          "club_hours",
          env,
          {
            method: "POST",

            body: {
              id: crypto.randomUUID(),
              ...payload
            }
          }
        );
      }

      return json({ ok: true });
    }

    if (
      action === "deleteEntry" &&
      request.method === "POST"
    ) {

      requireTeacher(me);

      const id =
        String(body.id || "");

      if (!id) {
        return json(
          { error: "Entry ID is required." },
          400
        );
      }

      await db(
        `club_hours?id=eq.${encodeURIComponent(id)}`,
        env,
        {
          method: "DELETE",
          prefer: "return=minimal"
        }
      );

      return json({ ok: true });
    }

    return json(
      { error: "Unknown action." },
      404
    );

  } catch (error) {

    console.error(error);

    return json(
      {
        error:
          error.message || "Server error."
      },
      error.status || 500
    );
  }
}
