import pkg from "pg";
const { Pool } = pkg;

export const db = new Pool({
  host: "localhost",
  user: "postgres",
  password: "194060le",
  database: "sgiptv"
});