const express = require('express');
const bodyParser = require('body-parser');
const session = require('express-session');
const { Pool } = require('pg');
const bcrypt = require('bcrypt');
require('dotenv').config();

const app = express();
const port = 3000;

const pool = new Pool({
    user: process.env.DB_USER,
    host: process.env.DB_HOST,
    database: process.env.DB_DATABASE,
    password: process.env.DB_PASSWORD,
    port: process.env.DB_PORT,
});

app.use(bodyParser.urlencoded({ extended: true }));
app.use(session({ secret: process.env.SESSION_SECRET || 'secreto', resave: false, saveUninitialized: true, secure: true, httpOnly: true }));

// Página de inicio
app.get('/', (req, res) => {
    res.sendFile(__dirname + '/index.html');
});

// Página de registro
app.get('/register', (req, res) => {
    res.sendFile(__dirname + '/registro.html');
});

app.post('/register', async (req, res) => {
    const { username, password } = req.body;

    try {
    
        // Validación de entrada
        if (isValidPassword(password) == false) {
            res.status(400).send('Datos de registro no válidos.');
            return;
        }
    

        const hashedPassword = await bcrypt.hash(password, 10);
        const result = await pool.query('INSERT INTO users (username, password) VALUES ($1, $2) RETURNING id', [username, hashedPassword]);

        // Registro exitoso
        req.session.userId = result.rows[0].id;
        res.send('Usuario registrado con éxito.');
    } catch (error) {
        console.error(error);
        // Registra el error de manera segura y proporciona un mensaje genérico al usuario
        res.status(500).send('Error en el registro. Por favor, inténtalo nuevamente.');
    }
});

// Página de inicio de sesión
app.get('/login', (req, res) => {
    res.sendFile(__dirname + '/inicio_sesion.html');
});

app.post('/login', async (req, res) => {
    const { username, password } = req.body;

    try {
        const result = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

        if (result.rows.length > 0) {
            const user = result.rows[0];
            const passwordMatch = await bcrypt.compare(password, user.password);

            if (passwordMatch) {
                req.session.userId = user.id;
                res.redirect('/register');
            } else {
                res.status(401).send('Contraseña incorrecta.');
            }
        } else {
            res.status(401).send('Usuario no encontrado.');
        }

    } catch (error) {
        console.error(error);
        res.status(500).send('Error en el inicio de sesión. Por favor, inténtalo nuevamente.');
    }
});

// Página de cambio de contraseña
app.get('/change-password', (req, res) => {
    res.sendFile(__dirname + '/cambio_contrasena.html');
});

// ... (otras configuraciones y rutas)

app.post('/change-password', async (req, res) => {
    const { username, newPassword } = req.body;

    try {
        // Busca al usuario por nombre de usuario en la base de datos
        const userResult = await pool.query('SELECT * FROM users WHERE username = $1', [username]);

        if (userResult.rows.length > 0) {
            const userId = userResult.rows[0].id;

            // Actualiza la contraseña en la base de datos
            const hashedNewPassword = await bcrypt.hash(newPassword, 10);
            await pool.query('UPDATE users SET password = $1 WHERE id = $2', [hashedNewPassword, userId]);

            // Redirige a la página de inicio o muestra un mensaje de éxito
            res.redirect('/');
        } else {
            // Usuario no encontrado
            res.status(401).send('Usuario no encontrado.');
        }
    } catch (error) {
        console.error(error);
        res.status(500).send('Error en el cambio de contraseña. Por favor, inténtalo nuevamente.');
    }
});

// ...





app.listen(port, () => {
    console.log(`Servidor iniciado en http://localhost:${port}`);
});

/*
// Funciones de validación
function isValidUsername(username) {
    // Agrega tu lógica de validación aquí
    return /^[a-zA-Z0-9_]+$/.test(username);
}
*/


function isValidPassword(password) {
    // Verifica si la longitud de la contraseña es al menos 8 caracteres
    if (password.length < 8) {
        return false;
    }

    // Verifica si la contraseña contiene al menos un carácter alfanumérico
    const alphanumericRegex = /^(?=.*[a-zA-Z0-9])/;
    if (!alphanumericRegex.test(password)) {
        return false;
    }

     
    let consecutiveNumbers = 0;
    // Verifica si la contraseña no tiene números consecutivos
    for (let i = 0; i < password.length - 1; i++) {
        const currentChar = password[i];
        const nextChar = password[i + 1];

        // La diferencia entre los caracteres consecutivos no debe ser 1 (números consecutivos)
        if (parseInt(nextChar) - parseInt(currentChar) === 1) {
            consecutiveNumbers = consecutiveNumbers + 1
        }
    }  

    if (consecutiveNumbers >= 3){
        return false
    } 
    

    // Si pasa todas las verificaciones, la contraseña es válida
    return true;
}

