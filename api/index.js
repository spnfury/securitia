// Vercel serverless entry (compatibilidad mientras el DNS siga apuntando a Vercel).
// En el servidor propio no se usa: pm2 ejecuta server/index.js directamente.
import app from "../server/index.js";

export default app;
