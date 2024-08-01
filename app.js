import express from "express"
import mongoose from "mongoose";
import bcrypt from "bcrypt"
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken"
import serviceAccountKey from './payment-platform-a263a-firebase-adminsdk-ih8uo-a1b34570ee.json' assert{type: 'json'}
import {getAuth} from "firebase-admin/auth"
import "dotenv/config"
import User from "./model/User.js"
import cors from "cors"
import admin from "firebase-admin"

const PORT = 3000
const allowedOrigin = process.env.ALLOWED_ORIGIN


const app = express();
app.use (express.json())
// cors enable frontend to connect to backend
 app.use (cors({origin: allowedOrigin}))

admin.initializeApp({
    credential: admin.credential.cert(serviceAccountKey)
})

mongoose.connect(process.env.DATABASE_URL, {autoIndex: true})
.then(() => console.log("mongondb connected"))
.catch(err => console.error(
    "MongoDB connection error:",err
))
//generating access code
const verifyToken = (req, res, next) => {

    const authHeader = req.headers['authorization'];
    const token = authHeader && authHeader.split(" ")[1];

    if(token == null){
        return res.status(401).json({error: "No access token"})
    }

    jwt.verify(token, process.env.SECRET_ACCESS_KEY, (err, user) =>{
        if(err) {
            return res.status(403).json({error: "Access token is invalid"})
        }

        req.user = user.id
        req.admin = user.admin
        next()
    })
};

// Utility functions....send data to front end
const formatDatatoSend = (user) => {
    const access_token = jwt.sign({ id: user._id }, process.env.SECRET_ACCESS_KEY);
    return {
        access_token,
       
        username: user.username,
        fullname: user.fullname,
        email: user.email
        

    };
}
// Regular expressions
const emailRegex = /^\w+([\.-]?\w+)*@\w+([\.-]?\w+)*(\.\w{2,3})+$/;
const passwordRegex = /^(?=.*\d)(?=.*[a-z])(?=.*[A-Z]).{6,20}$/;
const generateUsername = async (email) => {
    let username = email.split("@")[0];
    let isUsernameNotUnique = await User.exists({ "personal_info.username": username }).then(result => result);

    if (isUsernameNotUnique) {
        username += nanoid().substring(0, 5);
    }

    return username;
}


//sign up route



app.post("/signup", (req, res)=>{
  
    let {fullname, email, password} = req.body;

   
    //validating data from frontend*********************************************************************

    if(fullname.length < 3){
        return res.status(403).json({"error": "Fullname must be at least 3 letters long"})
    }


    if(!email.length){
        return res.status(403).json({"error": "Enter Email"})
    }

    if(!emailRegex.test(email)){
        return res.status(403).json({ "error":"Email is Invalid"})
    }

    if(!passwordRegex.test(password)){
        return res.status(403).json({"error": "Password should be 6 - 20 characters long with a numeric, 1 lowercase and 1 uppercase letters "}) 
    }

    bcrypt.hash(password, 10, async (err, hashed_password)=>{

            let username = await generateUsername(email);

            let user = new User({
                 fullname, email, password: hashed_password, username
            })

            user.save().then((u) =>{
                return res.status(200).json(formatDatatoSend(u))
            })

            .catch(err =>{

                if(err.code == 11000){
                    return res.status(500).json({"error": "Email Already Exists"})
                }
                return res.status(500).json({"error": err.message})
            })

    
    })
 
})





// app.post("/signup",async(req,res)=>{
//     let {fullname,email,password} = req.body

//     if (fullname.length < 3) {
//         return res.status(403).json({ "error": "Fullname must be at least 3 letters long" });
//     }

//     if (!email.length) {
//         return res.status(403).json({ "error": "Enter Email" });
//     }

//     if (!emailRegex.test(email)) {
//         return res.status(403).json({ "error": "Email Is Invalid" });
//     }

//     if (!passwordRegex.test(password)) {
//         return res.status(403).json({ "error": "password should be 6 - 20 characters long with a numeric, 1 lowercase and 1 uppercase letter" });
//     }


//     try {
//         const hashed_password = await bcrypt.hash(password, 10);
//         const username = await generateUsername(email);

//         const user = new User({
//              fullname, email, password: hashed_password, username 
//         });
//        //.save is saving data to database
//         await user.save();
//         //formatDatatoSend is send data from database to frontend
//         return res.status(200).json(  formatDatatoSend(user));
//     } catch (err) {
//         if (err.code === 11000) {
//             return res.status(500).json({ "error": "Email already exists" });
//         }
// return res.status(500).json({ "error": err.message });
//     }

// })

//sign in route

// app.post("/signin", async (req, res) => {
//     const { email, password } = req.body;

//     try {
//         const user = await User.findOne({email });

//         if (!user) {
//             return res.status(403).json({ "error": "Email not found" });
//         }

//         const result = await bcrypt.compare(password, user.password);

//         if (!result) {
//             return res.status(403).json({ "error": "Incorrect Password" });
//         } else {

//             return res.status(200).json(formatDatatoSend(user));


//         }
//     } catch (err) {
//         console.log(err.message);
//         return res.status(500).json({ "error": err.message });
//     }

// });

app.post("/signin", (req, res)=> {

    let { email, password} = req.body;
    
    User.findOne({  email})
    .then((user) => {

        if(!user){
            return res.status(403).json({"error": "Email not found"})
        }

        if(!user.google_auth){

            bcrypt.compare(password, user.password, (err, result) =>{

                if(err) {
                    return res.status(403).json({"error": "Error Occured while trying to login please try again"});
                }
    
                if(!result){
                    return res.status(403).json({"error": "Incorrect Password"})
                }else{
                    return res.status (200).json(formatDatatoSend(user))
                }
    
    
            })
            
        }else{
            return res.status(403).json({'error': "Account was created using google. Try login with Google."})
        }

   
    
    })

    .catch(err =>{
        console.log(err.message)
        return res.status(500).json({"error": err.message})
    })
})


//google  authenication**********************************************************************

app.post('/google-auth', async (req, res) =>{
    let {access_token} = req.body;

    getAuth()
    .verifyIdToken(access_token)
    .then(async (decodedUser) =>{


        let { email, name, picture} = decodedUser;

        picture = picture.replace("s96-c", "s384-c");

        let user = await User.findOne({ email}).select("fullname username profile_img google_auth")
            .then((u) =>{
                return u || null
            })

            .catch(err => {
                return res.status(500).json({"error" : err.message})
            })

            if(user) {//sign in 
                if(!user.google_auth){
                    return res.status(403).json({"error": "This account was signed up without google. Please log in with password to access the account"})
                }

            }
            else{//sign up

                let username = await generateUsername(email)
                user = new User ({
                    personal_info: {fullname: name, email, username},
                    google_auth: true
                })

                await user.save().then((u) =>{
                    user = u;
                })
                .catch(err =>{
                    return res.status(500).json({"error": err.message})
                })
            }

            return res.status(200).json(formatDatatoSend(user))
    })

    .catch(err => {
        return res.status(500).json({"error": "Failed to authenicate you with google. Try with some other google account"})
    })

})


app.listen(PORT,()=>{
    console.log("server started at port",PORT)
})

