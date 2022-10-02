require('dotenv').config();
const express = require('express');
const mongoose = require('mongoose');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');

// Utilizando framework
const app = express();

// config json response
app.use(express.json())


// MODELS
const User = require('./models/User')

// Open Route - Public Route - Disponibilizando para usuários
app.get('/', (req, res) => {
    res.status(200).json({ msg: 'Bem vindo a nossa API' });
})

// PRIVATE ROUTE
app.get('/user/:id', checkToken, async (req, res) => {
    const id = req.params.id;

    // check if USER EXIST
    const user = await User.findById(id, '-password');

    if (!user) {
        return res.status(404).json({ msg: 'Usuário NÃO ENCONTRADO!' })
    }
    res.status(200).json({ user });
})

//CHECK TOKET
function checkToken(req, res, next) {
    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(!token ) {
        return res.status(401).json({ msg: 'ACESSO NEGADO!' });
    };

    try {
        const secret = process.env.SECRET;
        jwt.verify(token, secret);

        next()
    } catch (error) {
        res.status(400).json({ msg: 'TOKEN INVÁLIDO!' })
    };
};

// REGISTER user
app.post('/auth/register', async (req, res) => {
    const { name, email, password, confirmPassword } = req.body;

    // VALIDATIONs
    if (!name) {
        return res.status(422).json({ msg: 'o nome é obrigatório!' })
    }
    if (!email) {
        return res.status(422).json({ msg: 'o email é obrigatório!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'o password é obrigatório!' })
    }
    if (password != confirmPassword) {
        return res.status(422).json({ msg: 'as senhas não conférem!' })
    }

    // check if USER EXIST
    const userExist = await User.findOne({ email: email });
    if (userExist) {
        return res.status(422).json({ msg: 'utilize outro email!' })
    }

    // create PASSWORD
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    //create USER
    const user = new User({
        name,
        email,
        password: passwordHash,
    })

    try {
        await user.save();
        res.status(201).json({ msg: 'Usuário criado com sucesso!' });

    } catch (error) {
        console.log(error);
        res.status(500)
            .json({
                msg: "ERRO---->Erro no SERVIDOR, tente mais tarde!",
            })
    }
})


//LOGIN AUTHENTICATE USER
app.post('/auth/login', async (req, res) => {
    const { email, password } = req.body

    // VALIDATIONs
    if (!email) {
        return res.status(422).json({ msg: 'o email é obrigatório!' })
    }
    if (!password) {
        return res.status(422).json({ msg: 'o senha é obrigatória!' })
    }
    // check if USER EXIST 404
    const user = await User.findOne({ email: email });
    if (!user) {
        return res.status(404).json({ msg: 'usuário não encontrado' })
    }
    // check if PASSWORD MATCH
    const checkPassword = await bcrypt.compare(password, user.password);
    if (!checkPassword) {
        return res.status(422).json({ msg: 'senha inválida' })
    }
    // VALIDATE SECRET
    try {
        const secret = process.env.secret;

        const token = jwt.sign(
            {
            id: user._id,
            },
            secret,
        )
        res.status(200).json({ msg: "Autenticação realizada com sucesso!", token })


    } catch (err) {
        console.log(error);
        res.status(500)
            .json({
                msg: "ERRO---->Erro no SERVIDOR, tente mais tarde!",
            })
    }
})


// CREDENTIALS 
const dbUser = process.env.DB_USER;
const dbPass = process.env.DB_PASS;

mongoose
    .connect(
        `mongodb+srv://${dbUser}:${dbPass}@cluster0.byvo80d.mongodb.net/?retryWrites=true&w=majority`
    )
    .then(() => {
        // API @ route 3000
        app.listen(3000);
        console.log('conectou ao banco!');
    })
    .catch((err) => console.log(err));

