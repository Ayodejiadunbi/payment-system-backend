import { Timestamp } from "mongodb"
import mongoose from "mongoose"
const userSchema = mongoose.Schema(
    {
            fullname: {
                type : String,
                lowercase : true,
                required : true,
                minlength : [3, " fullname must be atleat three chracter long"]

        },
        email :{
                type : String,
                lowercase : true,
                required : true,
                unique : true,
              

        },
        
        google_auth: {
            type: Boolean,
            default: false
        },



        password : {
            type : String,
            required : true,
            minlength : [8, " password must be at least 8 character long and ir must conatin an uppercase , lowercase and speacila character "]
        },
        username : {
            type : String ,
            unique : true,
            minlength : [3, "username name must be atleat 3 character long"]

        }
    },{
        timestamps:true
    }
)
export default mongoose.model("users",userSchema)