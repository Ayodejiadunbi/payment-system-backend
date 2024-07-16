import express from "express"
import mongoose from "mongoose";
import bcrypt from "bcrypt"
import { nanoid } from "nanoid";
import jwt from "jsonwebtoken"




import "dotenv/config"
import User from "./model/User.js"

const PORT = 8000



const app = express();
app.use (express.json())

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
app.post("/signup",async(req,res)=>{
    let {fullname,email,password} = req.body

    if (fullname.length < 3) {
        return res.status(403).json({ "error": "Fullname must be at least 3 letters long" });
    }

    if (!email.length) {
        return res.status(403).json({ "error": "Enter Email" });
    }

    if (!emailRegex.test(email)) {
        return res.status(403).json({ "error": "Email Is Invalid" });
    }

    if (!passwordRegex.test(password)) {
        return res.status(403).json({ "error": "password should be 6 - 20 characters long with a numeric, 1 lowercase and 1 uppercase letter" });
    }


    try {
        const hashed_password = await bcrypt.hash(password, 10);
        const username = await generateUsername(email);

        const user = new User({
             fullname, email, password: hashed_password, username 
        });
       //.save is saving data to database
        await user.save();
        //formatDatatoSend is send data from database to frontend
        return res.status(200).json(  formatDatatoSend(user));
    } catch (err) {
        if (err.code === 11000) {
            return res.status(500).json({ "error": "Email already exists" });
        }
return res.status(500).json({ "error": err.message });
    }

})

//sign in route

app.post("/signin", async (req, res) => {
    const { email, password } = req.body;

    try {
        const user = await User.findOne({email });

        if (!user) {
            return res.status(403).json({ "error": "Email not found" });
        }

        const result = await bcrypt.compare(password, user.password);

        if (!result) {
            return res.status(403).json({ "error": "Incorrect Password" });
        } else {

            return res.status(200).json(formatDatatoSend(user));


        }
    } catch (err) {
        console.log(err.message);
        return res.status(500).json({ "error": err.message });
    }

});


app.listen(PORT,()=>{
    console.log("server started at port",PORT)
})

