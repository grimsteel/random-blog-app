import session from "koa-session";
import Koa from "koa";
import { compile, defaultConfig, renderFile } from "squirrelly";
import { join } from "path";
import { dir } from "./utils.js";
import { DB } from "./db.js";
import { readFile } from "fs/promises";
import Router from "@koa/router";
import { bodyParser } from "@koa/bodyparser";
import { pbkdf2 as _pbkdf2, randomBytes, timingSafeEqual } from "crypto";
import { promisify } from "util";
import sanitize from "sanitize-html";
import { parse } from "marked";

const pbkdf2 = promisify(_pbkdf2);

async function compileView(view) {
  return compile(await readFile(join(dir(), "views", view), "utf8"));
}

const views = {
  index: await compileView("index.html"),
  login: await compileView("login.html"),
  signup: await compileView("signup.html"),
  create: await compileView("create.html"),
  error: await compileView("error.html"),
  view: await compileView("view.html"),
};

/**
 * Render a template
 * @param {import("koa").Context} ctx 
 * @param {keyof typeof views} view 
 * @param {any} data 
 */
function renderView(ctx, view, data) {
  const rendered = views[view]({ ...data, session: ctx.session }, { ...defaultConfig, views: [join(dir(), "views")] });

  ctx.body = rendered;
  ctx.type = "text/html";
}

async function hashPassword(password, salt) {
  return await pbkdf2(password, salt, 50_000, 64, "sha512");
}

function renderMarkdown(markdown) {
  return sanitize(parse(markdown));
}

/**
 * @param {import("koa").Context} ctx 
 * @param {import("koa").Next} next 
 */
function requireAuth(ctx, next) {
  if (!ctx.session.userId) {
    ctx.redirect("/login/");
    ctx.status = 303;
  } else {
    return next();
  }
}

/**
 * @param {import("koa").Context} ctx 
 * @param {import("koa").Next} next 
 */
function requireUnauth(ctx, next) {
  if (ctx.session.userId) {
    ctx.redirect("/");
    ctx.status = 303;
  } else {
    return next();
  }
}

/**
 * @param {import("koa").Context} ctx 
 * @param {import("koa").Next} next 
 */
function requireOwn(ctx, next) {
  if (ctx.session.userId === ctx.post.author) {
    return next();
  } else {
    renderView(ctx, "error", { message: "403 Forbidden" });
    ctx.status = 403;
  }
}

const db = new DB();
const app = new Koa();
const router = new Router();

app.keys = ["X9FLVTOWtc8xtsunpE9Z9nv0aEj6tC3qUKDxTP2x30U="];

app.use(session(app));
app.use(bodyParser());

// Custom 404
app.use(async (ctx, next) => {
  await next();
  if (ctx.status === 404) {
    renderView(ctx, "error", { message: "404 Not Found" });
    ctx.status = 404;
  }
});

router
  .get("/", ctx => {
    const data = {};

    if (ctx.session.userId) {
      data.username = db.getUserForId.get(ctx.session.userId).username;
    }

    data.posts = db.getPosts.all();

    renderView(ctx, "index", data);
  })
  .get("/signup/", requireUnauth, ctx => renderView(ctx, "signup", {}))
  .post("/signup/", requireUnauth, async ctx => {
    // Validate request
    const { username, password } = ctx.request.body;
    if (!(username && password)) {
      renderView(ctx, "signup", { errors: ["Username and password are required"], username });
      ctx.status = 400;
    } else {
      // Check for existing user
      const existingUser = db.getUserForName.get(username);
      if (existingUser) {
        renderView(ctx, "signup", { errors: ["Username taken"], username });
        ctx.status = 400;
      } else {
        // Generate salt and hash
        const salt = randomBytes(16);
        const hash = await hashPassword(password, salt);
        const { lastInsertRowid: userId } = db.createUser.run(username, hash, salt);
        ctx.session.userId = userId;

        ctx.redirect("/");
        ctx.status = 303;
      }
    }
  })
  .get("/login/", requireUnauth, ctx => renderView(ctx, "login", {}))
  .post("/login/", requireUnauth, async ctx => {
    // Validate request
    const { username, password } = ctx.request.body;
    if (!(username && password)) {
      renderView(ctx, "login", { errors: ["Username and password are required"], username });
      ctx.status = 400;
    } else {
      // Check for existing user
      const existingUser = db.getUserForName.get(username);
      if (!existingUser) {
        renderView(ctx, "login", { errors: ["Non existent user"], username });
        ctx.status = 400;
      } else {
        // Generate salt and hash
        const hash = await hashPassword(password, existingUser.salt);

        // Check password
        if (timingSafeEqual(hash, existingUser.password)) {
          ctx.session.userId = existingUser.id;
          ctx.redirect("/");
          ctx.status = 303;
        } else {
          renderView(ctx, "login", { errors: ["Incorrect password"], username });
          ctx.status = 400;
        }
      }
    }
  })
  .post("/logout/", requireAuth, ctx => {
    delete ctx.session.userId;
    ctx.redirect("/");
    ctx.status = 303;
  })
  .get("/posts/create/", requireAuth, ctx => renderView(ctx, "create", {}))
  .post("/posts/create/", requireAuth, ctx => {
    // Validate request
    const { title, content } = ctx.request.body;
    if (!(title && content)) {
      renderView(ctx, "create", { errors: ["Title and content are required"], title, content });
      ctx.status = 400;
    } else {
      const date = Date.now();
      
      const { lastInsertRowid: postId } = db.createPost.run(ctx.session.userId, title, content, date);
      
      ctx.redirect(`/posts/${postId}/`);
      ctx.status = 303;
    }
  })
  .param("post_id", (id, ctx, next) => {
    const post = db.getPostForId.get(id);
    if (!post) return ctx.status = 404;
    ctx.post = post;
    return next();
  })
  .get("/posts/:post_id(\\d+)/edit/", requireAuth, requireOwn, ctx => renderView(ctx, "create", { title: ctx.post.title, content: ctx.post.content, postId: ctx.post.id }))
  .post("/posts/:post_id(\\d+)/edit/", requireAuth, requireOwn, ctx => {
    // Validate request
    const { title, content } = ctx.request.body;
    if (!(title && content)) {
      renderView(ctx, "create", { errors: ["Title and content are required"], title, content, postId: ctx.post.id });
      ctx.status = 400;
    } else {            
      db.updatePostForId.run(title, content, ctx.post.id);
      
      ctx.redirect(`/posts/${ctx.post.id}/`);
      ctx.status = 303;
    }
  })
  .post("/posts/:post_id(\\d+)/delete/", requireAuth, requireOwn, ctx => {
    db.deletePostForId.run(ctx.post.id);

    ctx.redirect(`/`);
    ctx.status = 303;
  })
  .get("/posts/:post_id(\\d+)/", ctx => {
    // View
    const author = db.getUserForId.get(ctx.post.author);
    renderView(ctx, "view", { title: ctx.post.title, date: new Date(ctx.post.date), author, content: renderMarkdown(ctx.post.content) });
  });

app.use(router.routes());

app.listen(3000);
console.log("Serving on port 3000");