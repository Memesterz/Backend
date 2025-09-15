require("dotenv").config()
const jwt = require('jsonwebtoken')
const sanitizeHTML = require("sanitize-html")
const express = require("express")
const db = require("better-sqlite3")("ourApp.db")
db.pragma("journal_mode = wal")
const app = express()
const bcrypt = require("bcrypt")
const cookieParser = require("cookie-parser")

const createTables = db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
        
        `).run()
        db.prepare(`
            CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            Date TEXT,
            title STRING NOT NULL,
            body TEXT NOT NULL,
            authorid INTEGER,
            FOREIGN KEY (authorid) REFERENCES users (id)
            )
            `).run()
})

createTables()

app.set("view engine", "ejs")
app.use(express.urlencoded({extended:false}))
app.use(express.static("public"))
app.use(cookieParser())

app.use(function (req,res,next) {
    res.locals.errors = []
    try {
    const decoded = jwt.verify(req.cookies.LoginCookie,process.env.JWTSECRET)
    req.user = decoded
    } catch(err) {
        req.user = false
    }
    res.locals.user = req.user
    console.log("Middleware", req.user)
    next()
})

app.get("/", (req,res) => {
    if (req.user) {
        return res.render("dashboard")
    }
    res.render("homepage")
})

app.get("/logout", (req,res) => {
    res.clearCookie("LoginCookie")
    res.redirect("/")
})

app.get("/login", (req,res) => {
    res.render("login")
})

app.post("/login", (req,res) => {
    let errors = []

    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    if (req.body.username.trim() == "") errors = ["Empty Username/Password"]
    if (req.body.password == "") errors = ["Empty Username/Password"]

    if (errors.length) {
        return res.render("login", {errors})
    }

    const findUser = db.prepare("SELECT * FROM users WHERE USERNAME = ?")
    const userResponse = findUser.get(req.body.username)

    if (!userResponse) {
        errors = ["Empty Username/Password"]
        return res.render("login", {errors})
    }

    const userCheck = bcrypt.compareSync(req.body.password, userResponse.password)

    if (!userCheck) {
        errors = ["Invalid Username/Password"]
        return res.render("login", {errors})
    }

    const ourTokenValue = jwt.sign({exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,userid: userResponse.id, username: userResponse.username}, process.env.JWTSECRET)

    res.cookie("LoginCookie", ourTokenValue,{
        httpOnly: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })

    res.redirect("/")
})

function LoginCheck(req,res,next) {
    if (req.user) {
        return next()
    }
    res.redirect("/")
}

function PostValidation(req) {
    const errors = []

    if (typeof req.body.title !== "string") req.body.title = ""
    if (typeof req.body.body !== "string") req.body.body = ""

    req.body.title = sanitizeHTML(req.body.title.trim(), {allowedTags: [], allowedAttributes: {}})
    req.body.body = sanitizeHTML(req.body.body.trim(), {allowedTags: [], allowedAttributes: {}})

    if (!req.body.title) errors.push("No Title")
    if (!req.body.body) errors.push("No Body")

    return errors
}

app.get("/create-post", LoginCheck, (req,res) => {
    res.render("create-post")
})

app.post("/create-post", LoginCheck, (req,res) => {
    const errors = PostValidation(req)

    if (errors.length) {
        return res.render("create-post", {errors})
    }

    const ourStatement = db.prepare(`INSERT INTO posts (title,body,authorid,Date) VALUES (?,?,?,?)`)
    const result = ourStatement.run(req.body.title, req.body.body,req.body.userid, new Date().toISOString())
    
    const getPost = db.prepare("SELECT * FROM posts WHERE ROWID = ?")
    const Post = getPost.get(result.lastInsertRowid)
    res.redirect(`/post/${Post.id}`)
})

app.post("/register", (req,res) => {
    const errors = []

    if (typeof req.body.username !== "string") req.body.username = ""
    if (typeof req.body.password !== "string") req.body.password = ""

    req.body.username = req.body.username.trim()

    if (!req.body.username) errors.push("No Username")
    if (req.body.username && req.body.username.length < 3) errors.push("Username Too Short must be 3 Characters")
    if (req.body.username && req.body.username.length > 10) errors.push("Username Too Long must be less than 10 Characters")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username has Invalid Characters")
    
    const usernameLookup = db.prepare("SELECT * FROM users WHERE username = ?")
    const usernameCheck = usernameLookup.get(req.body.username)
    if (usernameCheck) errors.push("That Username is Taken")

    if (!req.body.password) res.locals.errors.push("No Password")
    if (req.body.password && req.body.password.length < 3) errors.push("Password Too Short must be 3 Characters")
    if (req.body.password && req.body.password.length > 10) errors.push("Password Too Long must be less than 10 Characters")
    
    if (errors.length) {
    return res.render("homepage", { errors })
    } else {
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    const result = ourStatement.run(req.body.username, req.body.password)

    const lookup = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const OurUser = lookup.get(result.lastInsertRowid)

    const ourTokenValue = jwt.sign(
        {
        exp: Math.floor(Date.now() / 1000) + 60 * 60 * 24,
        userid: OurUser.id,
        username: OurUser.username
        }, 
        process.env.JWTSECRET
    )

    res.cookie("LoginCookie", ourTokenValue,{
        httpOnly: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })

    res.redirect("/")
    }
})

app.listen(3000)
