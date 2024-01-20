import Database from "better-sqlite3";
import { join } from "path";
import { dir } from "./utils.js";
import { readFile } from "fs/promises";

export class DB {
  constructor() {
    const db = new Database(join(dir(), "app.db"), { fileMustExist: false });
    db.pragma("foreign_keys = ON");
    this.db = db;

    this.#initDb().then(() => 
      this.#prepareStatements()
    );
  }
  async #initDb() {
    const schema = await readFile(join(dir(), "schema.sql"), "utf8");
    this.db.exec(schema);
  }
  #prepareStatements() {
    this.getUserForId = this.db.prepare("SELECT id, username, password, salt FROM users WHERE id = ?");
    this.getUserForName = this.db.prepare("SELECT id, username, password, salt FROM users WHERE username = ?");

    this.createUser = this.db.prepare("INSERT INTO users (username, password, salt) VALUES (?, ?, ?)");

    this.createPost = this.db.prepare("INSERT INTO posts (author, title, content, date) VALUES (?, ?, ?, ?)");
    this.getPosts = this.db.prepare("SELECT id, title, date FROM posts ORDER BY date DESC");
    this.getPostForId = this.db.prepare("SELECT id, author, title, content, date FROM posts WHERE id = ?");
    this.updatePostForId = this.db.prepare("UPDATE posts SET title = ?, content = ? WHERE id = ?");
    this.deletePostForId = this.db.prepare("DELETE FROM posts WHERE id = ?");
  }
}

/**
 * @typedef {{ id: number, name: string, content: string, author: number, created: number }} Post
 */
