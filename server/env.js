import { fileURLToPath } from "url";
import { dirname, join } from "path";
import dotenv from "dotenv";

const __dirname = dirname(fileURLToPath(import.meta.url));
// Resolve .env relative to the server file so cwd doesn't matter.
dotenv.config({ path: join(__dirname, "..", ".env") });
