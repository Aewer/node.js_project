const express = require("express");
const dotenv = require("dotenv");
const { Client } = require('pg');
const bcrypt = require("bcryptjs")

const app = express();

dotenv.config({ path: './.env'});

const client = new Client({
    host: process.env.PGHOST,
    user: process.env.PGUSER,
    password: process.env.PGPASSWORD,
    database: process.env.PGDATABASE,
    port: 5432
});

client.connect(function(err) {
    if(err) {
        console.log(err);
    } else {
        console.log("Database connected");
    }
})

app.set('view engine', 'ejs');

app.get("/", (req, res) => {
    res.render("index");
})

app.get("/register", (req, res) => {
    res.render("register")
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.use(express.urlencoded({extended: 'false'}));
app.use(express.json());

app.post("/auth/register", async (req, res) => {
    const { name, password } = req.body;

    try {
        const result = await client.query('SELECT * FROM users WHERE name = $1', [name]);

        if (result.rows.length > 0) {
            return res.status(400).send('Name is already in use');
        }

        let hashedPassword = await bcrypt.hash(password, 8);
        client.query('INSERT INTO users (name, password) VALUES ($1, $2)', [name, hashedPassword], (err) => {
            if (err) {
                console.log(err);
                return res.status(500).send('Internal Server Error');
            } else {
                return res.status(200).send('Registration successful');
            }
        });
    } catch (error) {
        console.error(error);
        return res.status(500).send('Internal Server Error');
    }
});

app.post("/auth/login", async (req, res) => {
    const { name, password } = req.body;

    try {
        const result = await client.query('SELECT * FROM users WHERE name = $1', [name]);

        if (result.rows.length === 0) {
            return res.status(401).send('User not found');
        }

        const user = result.rows[0];
        const passwordMatch = await bcrypt.compare(password, user.password);

        if (!passwordMatch) {
            return res.status(401).send('Invalid password');
        }

        return res.status(200).send('Login successful');
    } catch (error) {
        console.error(error);
        return res.status(500).send('Internal Server Error');
    }
});



app.listen(5000, ()=> {
    console.log("Server starts on port 5000")
})