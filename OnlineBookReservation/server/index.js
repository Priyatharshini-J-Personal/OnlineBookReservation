const express = require('express');
const mysql = require('mysql2');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const bodyParser = require('body-parser');
const session = require('express-session');
const MySQLStore = require('express-mysql-session')(session);
require('dotenv').config();

const app = express();
const port = 3001;


const sessionStore = new MySQLStore({
    port: 3306,
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

app.use(cors({
    origin: 'http://localhost:3000',
    credentials: true
}));

app.use(bodyParser.json());

app.use(session({
    name: 'connect.sid',
    key: 'session_cookie_name',
    secret: 'Online book reservation',
    resave: false,
    saveUninitialized: false,
    store: sessionStore,
    cookie: {
        secure: false,
        httpOnly: true,
        maxAge: 1000 * 60 * 60 * 24,
    }
}));

const db = mysql.createConnection({
    host: process.env.DB_HOST,
    user: process.env.DB_USER,
    password: process.env.DB_PASSWORD,
    database: process.env.DB_NAME
});

db.connect(err => {
    if (err) {
        console.error('error connecting: ' + err.stack);
        return;
    }
    console.log('connected as id ' + db.threadId);
});

app.get('/current_user', (req, res) => {
    if (req.session.user) {
        return res.status(200).send({ "user": req.session.user });
    } else {
        return res.status(401).send({ error: "Unauthorised" });
    }
});

app.post('/login', (req, res) => {
    const { email, password } = req.body;
    db.query('SELECT * FROM users WHERE email = ?', [email], async (err, results) => {
        if (err) {
            return res.status(500).send({ error: 'Database error' });
        }
        if (results.length === 0) {
            return res.status(401).send({ error: 'User is not registered.' });
        }
        const user = results[0];
        const isMatch = await bcrypt.compare(password, user.password);

        if (isMatch) {
            req.session.user = {
                id: user.id,
                email: user.email,
                name: user.first_name + " " + user.last_name
            };
            return res.send({ success: isMatch, user: req.session.user });
        } else {
            return res.status(401).send({ error: 'Incorrect password' });
        }
    });
});

app.post('/register', async (req, res) => {
    const { first_name, last_name, email, mobile, password } = req.body;
    const salt = await bcrypt.genSalt(10);
    const hashedPassword = await bcrypt.hash(password, salt);
    db.query('INSERT INTO users (first_name, last_name, email, mobile, password) VALUES (?, ?, ?, ?, ?)',
        [first_name, last_name, email, mobile, hashedPassword], function (err, result) {
            if (err) {
                console.error('error while registering', JSON.stringify(err));
                if (err.code == "ER_DUP_ENTRY") {
                    return res.status(500).send({
                        status: 'failure',
                        message: 'This user is already registered.'
                    });
                } else {
                    return res.status(500).send({
                        status: 'failure',
                        message: 'User registeration failed.'
                    });
                }
            }
            return res.status(200).send({
                status: 'success',
                message: "User registered successfully."
            })
        });
});

app.get('/featuredBooks', (req, res) => {

    db.query('SELECT b.*, r.Booked_dates FROM books b LEFT JOIN reservation r ON b.id = r.Book_id WHERE b.featured = 1;', (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        res.status(200).send({ "featured": results });
    });
});

app.post('/searchedBooks', (req, res) => {
    const { searchText, searchBy } = req.body;
    const query = `SELECT b.*, GROUP_CONCAT(r.Booked_dates) AS Booked_dates FROM books b LEFT JOIN reservation r ON b.id = r.Book_id WHERE b.${searchBy} LIKE '%${searchText}%' GROUP BY b.id`;
    db.query(query, (err, results) => {
        if (err) {
            console.log(err)
            return res.status(500).send(err);
        }
        res.status(200).send({ "searchedBooks": results });
    });
});

app.post('/reserve', (req, res) => {
    const { Book_id, Booked_by, Booked_dates } = req.body;
    const bookedDatesString = JSON.stringify(Booked_dates);
    const query = `
    INSERT INTO reservation (Book_id, Booked_by, Booked_dates)
    VALUES (?, ?, ?)
  `;
    db.query(query, [Book_id, Booked_by, bookedDatesString], async (err, results) => {
        if (err) {
            console.log("error while reserving - ", err);
            return res.status(500).send({ error: 'Error occured while reserving the book.' });
        }
        return res.status(200).send({ success: true, message: "Books reserved successfully." });
    });
});

app.post('/shelf', (req, res) => {
    const { booked_by } = req.body;
    const query = `SELECT
    r.Book_id,
    b.Title,
    b.Author,
    b.Cover_image,
    r.Booked_by,
    GROUP_CONCAT(r.Booked_dates ORDER BY r.Booked_dates ASC) AS Booked_dates
  FROM
    reservation r
  LEFT JOIN
    books b
  ON
    r.Book_id = b.id
  WHERE
    r.Booked_by = ?
  GROUP BY
    r.Book_id, b.Title, b.Author, b.Cover_image, r.Booked_by`
    db.query(query, [booked_by], (err, results) => {
        if (err) {
            return res.status(500).send(err);
        }
        const parseAndConcatenateDates = (bookedDatesStr) => {
            const dateStrings = bookedDatesStr.split('],[');
            dateStrings[0] = dateStrings[0].replace('[', '');
            dateStrings[dateStrings.length - 1] = dateStrings[dateStrings.length - 1].replace(']', '');
            const parsedDates = dateStrings.map(dateStr => JSON.parse(`[${dateStr}]`));
            return [].concat(...parsedDates);
        };
        const formatDate = (date) => {
            const parsedDate = new Date(date);
            if (isNaN(parsedDate)) {
                console.error(`Invalid date value: ${date}`);
                return null;
            }
            return parsedDate.toISOString().split('T')[0];
        };
        const today = formatDate(new Date());
        const laterShelf = [];
        const presentShelf = [];
        const futureShelf = [];

        results.forEach(book => {

            book.Booked_dates = parseAndConcatenateDates(book.Booked_dates);
            book.Booked_dates.forEach(date => {
                const formattedDate = formatDate(date);
                if (formattedDate < today) {
                    laterShelf.push({ ...book, Booked_dates: [date] });
                } else if (formattedDate === today) {
                    presentShelf.push({ ...book, Booked_dates: [date] });
                } else {
                    futureShelf.push({ ...book, Booked_dates: [date] });
                }
            });
        });
        const combineBooks = (shelf) => {
            const booksMap = new Map();
            shelf.forEach(book => {
                const { Book_id, Title, Author, Cover_image, Booked_by, Booked_dates } = book;
                if (!booksMap.has(Book_id)) {
                    booksMap.set(Book_id, {
                        Book_id,
                        Title,
                        Author,
                        Cover_image,
                        Booked_by,
                        Booked_dates: []
                    });
                }
                booksMap.get(Book_id).Booked_dates.push(...Booked_dates);
            });
            return Array.from(booksMap.values());
        };
        const pastBooks = combineBooks(laterShelf);
        const presentBooks = combineBooks(presentShelf);
        const futureBooks = combineBooks(futureShelf);
        res.status(200).send({ pastBooks, presentBooks, futureBooks });
    });
});

app.post('/logout', (req, res) => {
    req.session.destroy(err => {
        if (err) {
            return res.status(500).send('Failed to log out');
        }
        res.clearCookie('connect.sid', { path: '/' });
        res.send('Logged out successfully');
    });
});

app.listen(port, () => {
    console.log(`Server running on port ${port}`);
});
