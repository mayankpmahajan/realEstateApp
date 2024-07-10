import bcrypt from 'bcrypt';
import prisma from '../lib/prisma.js';
import jwt from 'jsonwebtoken';

export const register = async (req, res) => {
    const { username, email, password } = req.body;
  
    try {
      // HASH THE PASSWORD
  
      const hashedPassword = await bcrypt.hash(password, 10);
  
      console.log(hashedPassword);
  
      // CREATE A NEW USER AND SAVE TO DB
      const newUser = await prisma.user.create({
        data: {
          username,
          email,
          password: hashedPassword,
        },
      });
  
      console.log(newUser);
  
      res.status(201).json({ message: "User created successfully" });
    } catch (err) {
      console.log(err);
      res.status(500).json({ message: "Failed to create user!" });
    }
  };

export const login = async (req, res) =>{
    const {username, password} = req.body;

    try{
    //check if the user exists or not
    const user = await prisma.user.findUnique({
        where: {username}
    })

    if(!user) return res.status(401).json({message: "Invalid credentials"});

    //check if passowrd is correct

    const isPasswordValid = await bcrypt.compare(password, user.password);
    if(!isPasswordValid) return res.status(401).json({message: "Invalid Credentials"});

    const age = 1000 * 60 * 60 * 24 * 7;

    const token = jwt.sign({
        id: user.id,
    }, process.env.JWT_SECRET_KEY, {expiresIn: age});


    //generate cookie token and sent it to the user

    const {password: userPassword, ...userInfo} = user;
    res.cookie("token", token, {
        httpOnly: true,
        // secure: true
        maxAge: age,
    }).status(200).json(userInfo);

    } catch(err){
        console.log(err);
        res.status(500).json({message: "Failed to login"});
    }
}

export const logout = (req, res) =>{
    res.clearCookie("token").status(200).json({message: "Logout Successful"});
}