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


// Private Route
app.get("/user/:id", checkToken, async (req, res) => {

    const id = req.params.id

    // check if user exists
    const user = await User.findById(id, '-password')

    if(!user){
        return res.status(404).json({msg:'usuario não encontrado'})
    }

    return res.status(200).json({user})
    
})

// funcao middlewere para checar se o token existe na requisição
function checkToken(req, res, next){
    const authHeader = req.headers['authorization']
    const token = authHeader && authHeader.split(' ')[1]

    if (!token){
        return res.status(401).json({msg: 'acesso negado!'})
    }

    try {

        const secret = process.env.SECRET

        jwt.verify(token,secret)

        next()
        
    } catch (error) {
        res.status(400).json({msg:'Token invalido'})
    }
}

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
        password: passwordHash,
    })

    try {

        await user.save()

        res.status(201).json({msg:'Usuario criado com sucesso'})

    } catch (err){

        res.status(500).json({msg: "error"})
    }

    return res.status(200).json({msg:`nome: ${name}`})

})

app.post('/auth/user', async (req, res) => {

    const {email, password} = req.body

    // validations
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

    // check if user exists

    const user = await User.findOne({email: email})

    if(!user){
        return res.status(404).json({msg:'usuario não existe'})
    }

    const checkPassword = await bcrypt.compare(password,user.password)
    if (!checkPassword){
        return res.status(422).json({msg: 'Senha inválida!'})
    }

    try {
        const secret = process.env.SECRET
        const token = jwt.sign({
            id:user._id
        },
        secret,
    )

    res.status(200).json({msg: 'Autenticação realizada com sucesso', token})
        
    } catch (error) {
        console.log(error);
        res.status(500).json({msg:'Aconteceu um erro no servidor, tente novamente mais tarde'})
        
    }

    return res.status(201).json(user)


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

