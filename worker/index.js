// Worker de Cloudflare del inventario de monedas.
// La pagina (GitHub Pages) le manda los cambios con una clave; el Worker los guarda en el
// repositorio de GitHub con su propia llave, asi Miguel no necesita el token de GitHub.
//
// Secretos (se ponen con `wrangler secret put NOMBRE`, nunca van en el codigo):
//   USUARIO       el usuario para entrar
//   CLAVE         la clave para entrar
//   GITHUB_TOKEN  llave de GitHub con permiso de escritura en el repositorio
//   FIRMA         texto al azar para firmar las sesiones

const REPO = 'miguelv3g4-ctrl/inventario-monedas';
const ORIGENES = ['https://miguelv3g4-ctrl.github.io'];
const DIAS_SESION = 30;
const NOMBRE_FOTO = /^[A-Za-z0-9_-]{1,80}\.jpg$/;
const MAX_FOTO = 8 * 1024 * 1024;
const MAX_DATOS = 4 * 1024 * 1024;

const enc = new TextEncoder();
const b64url = buf => btoa(String.fromCharCode(...new Uint8Array(buf))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
const deB64url = s => Uint8Array.from(atob(s.replace(/-/g, '+').replace(/_/g, '/')), c => c.charCodeAt(0));
function b64(bytes) { let s = ''; for (let i = 0; i < bytes.length; i += 8192) s += String.fromCharCode.apply(null, bytes.subarray(i, i + 8192)); return btoa(s); }

async function hmac(secreto, texto) {
  const k = await crypto.subtle.importKey('raw', enc.encode(secreto), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  return new Uint8Array(await crypto.subtle.sign('HMAC', k, enc.encode(texto)));
}
function iguales(a, b) { if (a.length !== b.length) return false; let d = 0; for (let i = 0; i < a.length; i++) d |= a[i] ^ b[i]; return d === 0; }

async function crearSesion(env) {
  const carga = b64url(enc.encode(JSON.stringify({ v: Date.now() + DIAS_SESION * 864e5 })));
  return { sesion: carga + '.' + b64url(await hmac(env.FIRMA, carga)), vence: Date.now() + DIAS_SESION * 864e5 };
}
async function sesionValida(env, req) {
  const m = /^Bearer ([\w-]+)\.([\w-]+)$/.exec(req.headers.get('Authorization') || '');
  if (!m) return false;
  if (!iguales(await hmac(env.FIRMA, m[1]), deB64url(m[2]))) return false;
  try { return JSON.parse(new TextDecoder().decode(deB64url(m[1]))).v > Date.now(); } catch (e) { return false; }
}

function github(env, metodo, ruta, cuerpo, crudo) {
  return fetch('https://api.github.com/repos/' + REPO + '/contents/' + ruta, {
    method: metodo,
    headers: {
      Authorization: 'Bearer ' + String(env.GITHUB_TOKEN).trim(), 'User-Agent': 'inventario-monedas-worker',
      Accept: crudo ? 'application/vnd.github.raw' : 'application/vnd.github+json', 'X-GitHub-Api-Version': '2022-11-28',
      ...(cuerpo ? { 'Content-Type': 'application/json' } : {})
    },
    body: cuerpo ? JSON.stringify(cuerpo) : undefined
  });
}

// intentos fallidos por IP (en memoria de esta instancia; suficiente para frenar adivinanzas)
const fallos = new Map();

export default {
  async fetch(req, env) {
    const origen = req.headers.get('Origin') || '';
    const cors = {
      'Access-Control-Allow-Origin': ORIGENES.includes(origen) ? origen : ORIGENES[0],
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Authorization, Content-Type, X-Mensaje',
      'Access-Control-Max-Age': '86400', Vary: 'Origin', 'Cache-Control': 'no-store'
    };
    const json = (obj, status = 200) => new Response(JSON.stringify(obj), { status, headers: { ...cors, 'Content-Type': 'application/json; charset=utf-8' } });
    if (req.method === 'OPTIONS') return new Response(null, { status: 204, headers: cors });
    if (origen && !ORIGENES.includes(origen)) return json({ error: 'origen no permitido' }, 403);
    if (!env.CLAVE || !env.FIRMA) return json({ error: 'Falta configurar el Worker (secretos).' }, 503);

    const url = new URL(req.url), ruta = url.pathname;
    try {
      if (ruta === '/entrar' && req.method === 'POST') {
        const ip = req.headers.get('CF-Connecting-IP') || '?', f = fallos.get(ip) || { n: 0, t: 0 };
        if (f.n >= 5 && Date.now() - f.t < 15 * 60e3) return json({ error: 'Demasiados intentos. Espera 15 minutos.' }, 429);
        const { usuario, clave } = await req.json().catch(() => ({}));
        // el usuario no distingue mayusculas, tildes ni espacios de mas; la clave si es exacta
        const norm = t => String(t || '').normalize('NFD').replace(/[̀-ͯ]/g, '').toLowerCase().replace(/\s+/g, ' ').trim();
        const usuarioOk = !env.USUARIO || norm(usuario) === norm(env.USUARIO);
        const ok = typeof clave === 'string' && iguales(await hmac(env.FIRMA, clave), await hmac(env.FIRMA, env.CLAVE)) && usuarioOk;
        if (!ok) {
          fallos.set(ip, { n: Date.now() - f.t < 15 * 60e3 ? f.n + 1 : 1, t: Date.now() });
          await new Promise(r => setTimeout(r, 800));
          return json({ error: 'Usuario o clave incorrectos.' }, 401);
        }
        fallos.delete(ip);
        return json(await crearSesion(env));
      }

      if (!(await sesionValida(env, req))) return json({ error: 'Sesión vencida. Vuelve a entrar con la clave.' }, 401);

      // imagenes privadas (capturas de catalogo): solo con sesion, nunca en el repositorio publico
      const mp = /^\/privado\/([A-Za-z0-9_-]{1,80}\.jpg)$/.exec(ruta);
      if (mp && req.method === 'GET') {
        if (!env.INVENTARIO_PRIVADO) return json({ error: 'Falta el almacén privado.' }, 503);
        const img = await env.INVENTARIO_PRIVADO.get(mp[1], 'arrayBuffer');
        if (!img) return json({ error: 'No existe' }, 404);
        return new Response(img, { headers: { ...cors, 'Content-Type': 'image/jpeg', 'Cache-Control': 'private, max-age=86400' } });
      }

      if (ruta === '/datos' && req.method === 'GET' && !env.GITHUB_TOKEN) {
        // sin llave de GitHub todavia: se lee la copia publica (solo para ver)
        const r = await fetch('https://raw.githubusercontent.com/' + REPO + '/main/datos.json?t=' + Date.now(), { headers: { 'User-Agent': 'inventario-monedas-worker' } });
        return json({ datos: r.ok ? await r.json() : {}, sha: null, soloVer: true });
      }
      if (!env.GITHUB_TOKEN) return json({ error: 'Falta conectar GitHub en Cloudflare (GITHUB_TOKEN). Por ahora solo se puede ver.' }, 503);
      if (ruta === '/datos' && req.method === 'GET') {
        const r = await github(env, 'GET', 'datos.json');
        if (r.status === 404) return json({ datos: {}, sha: null });
        if (r.status === 401) {
          // pista sin mostrar la llave: tipo y largo de lo que se guardo en Cloudflare
          const t = String(env.GITHUB_TOKEN).trim(), tipo = /^github_pat_/.test(t) ? 'github_pat_' : /^gh[po]_/.test(t) ? t.slice(0, 4) : 'otro formato';
          return json({ error: 'GitHub no acepta la llave guardada en Cloudflare (tipo: ' + tipo + ', ' + t.length + ' caracteres). Revisa que sea el token completo y vigente.' }, 502);
        }
        if (!r.ok) return json({ error: 'GitHub respondió ' + r.status }, 502);
        const j = await r.json();
        return json({ datos: JSON.parse(new TextDecoder().decode(Uint8Array.from(atob(j.content.replace(/\s/g, '')), c => c.charCodeAt(0))) || '{}'), sha: j.sha });
      }
      if (ruta === '/datos' && req.method === 'PUT') {
        const texto = await req.text();
        if (texto.length > MAX_DATOS) return json({ error: 'Datos demasiado grandes.' }, 413);
        const { contenido, sha, mensaje } = JSON.parse(texto);
        JSON.parse(contenido); // solo se guarda JSON valido
        const cuerpo = { message: String(mensaje || 'Cambio en el inventario').slice(0, 200), content: b64(enc.encode(contenido)) };
        if (sha) cuerpo.sha = sha;
        const r = await github(env, 'PUT', 'datos.json', cuerpo);
        if (r.status === 409 || r.status === 422) return json({ conflicto: true }, 409);
        if (!r.ok) return json({ error: 'GitHub respondió ' + r.status }, 502);
        return json({ sha: (await r.json()).content.sha });
      }

      const mf = /^\/fotos\/([^/]+)$/.exec(ruta);
      if (mf) {
        const nombre = decodeURIComponent(mf[1]);
        if (!NOMBRE_FOTO.test(nombre)) return json({ error: 'Nombre de foto no válido.' }, 400);
        if (req.method === 'GET') {
          const r = await github(env, 'GET', 'fotos/' + nombre, null, true);
          if (!r.ok) return json({ error: 'No existe' }, 404);
          return new Response(r.body, { headers: { ...cors, 'Content-Type': 'image/jpeg' } });
        }
        if (req.method === 'PUT') {
          const bytes = new Uint8Array(await req.arrayBuffer());
          if (!bytes.length || bytes.length > MAX_FOTO) return json({ error: 'Foto vacía o demasiado grande.' }, 413);
          if (bytes[0] !== 0xff || bytes[1] !== 0xd8) return json({ error: 'Solo se aceptan fotos JPG.' }, 400);
          let mensaje = 'Foto nueva'; try { mensaje = decodeURIComponent(req.headers.get('X-Mensaje') || '') || mensaje; } catch (e) {}
          const r = await github(env, 'PUT', 'fotos/' + nombre, { message: mensaje.slice(0, 200), content: b64(bytes) });
          if (!r.ok) return json({ error: 'GitHub respondió ' + r.status + ' al subir la foto.' }, 502);
          return json({ nombre });
        }
        if (req.method === 'DELETE') {
          const m = await github(env, 'GET', 'fotos/' + nombre);
          if (m.status === 404) return json({ ok: true });
          if (!m.ok) return json({ error: 'GitHub respondió ' + m.status }, 502);
          const r = await github(env, 'DELETE', 'fotos/' + nombre, { message: 'Quitar foto', sha: (await m.json()).sha });
          return r.ok ? json({ ok: true }) : json({ error: 'GitHub respondió ' + r.status }, 502);
        }
      }
      return json({ error: 'No existe' }, 404);
    } catch (e) {
      return json({ error: 'Error: ' + (e.message || e) }, 500);
    }
  }
};
