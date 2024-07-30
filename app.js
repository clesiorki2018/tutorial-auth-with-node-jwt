/** Arquivo app.js */
/** Este arquivo é o código principal da aplicação */


/** Imports */
require('dotenv').config() // Configurar as variáveis de ambiente
const express = require('express') // criação da api
const mongoose = require('mongoose')  // trabalhar com banco de dados mongo
const bcrypt = require('bcrypt') // trabalhar com senhas e hash
const jwt = require('jsonwebtoken') // trabalhar com os pacotes jwt ao longo do aplicativo


const app = express()

// Config JSON response
app.use(express.json())


// Models
const User = require('./models/User')

// Open Route - Public Route
app.get('/',(rec,res) => {
    res.status(200).json({msg:'bem vindo a api'})
})

// Register User
app.post('/auth/register', async(req, res) => {

    const {name, email, password, confirmpassword} = req.body

    // validations
    if(!name){

        return res
        .status(422) // 422 quando o servidor entende a requisição mas os dados estão incorretos
        .json({msg:'o nome é obrigatório'})
    }

    if(!email){

        return res
        .status(422)
        .json({msg:'o email é obrigatório'})
    }
    if(!password){

        return res
        .status(422)
        .json({msg:'o password é obrigatório'})
    }
    if(!confirmpassword){

        return res
        .status(422)
        .json({msg:'o confirmpassword é obrigatório'})
    }

    if(password !== confirmpassword){
        return res.status(422).json({msg:'As senhas não conferem!'})
    }

    // check if user exists
    // Tem que checar para não haver usuarios duplicados
    const userExists = await User.findOne({email: email})
    if(userExists){
        return res.status(422).json({msg:'O email ja existe!'})
    }

    // Create password
    const salt = await bcrypt.genSalt(12)
    const passwordHash = await bcrypt.hash(password, salt)

    // create user
    const user = new User({
        name,
        email,
        password,
    })

    





    return res.status(200).json({msg:`nome: ${name}`})

})

// Credentials
const dbUser = process.env.DB_USER
const dbPassword = process.env.DB_PASS


mongoose.connect(
    `mongodb+srv://${dbUser}:${dbPassword}@authjwtnode.vtbgzyl.mongodb.net/?retryWrites=true&w=majority&appName=authjwtnode`
).then(() => {
    app.listen(3000)
    console.log('connectou com sucesso!!');
    
}).catch((err) => console.log(err))

