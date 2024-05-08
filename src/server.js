import express from "express";
import bodyParser from "body-parser";
import viewEngine from "./config/viewEngine";
import initWebRoutes from "./route/web";
import cors from 'cors';
import { createServer } from 'node:http';
import { Server } from 'socket.io';
import SocketServices from './services/socketIOService';
import mqttClient from './controllers/mqttClientController';
import mongoose from 'mongoose';
import userRouter from './route/user';
import gardenRouter from './route/garden';
import deviceRouter from './route/device';
import LogRouter from './route/ActivityLog';
import bcrypt from 'bcryptjs';
import jwt from 'jsonwebtoken';
import cookieParser from 'cookie-parser';


require("dotenv").config();

let app = express();
const server = createServer(app);
const io = new Server(server, {
  cors: {
    origin: "*",
    methods:["GET", "POST"],
  }
});
global._io = io;
//config app

app.use(cookieParser());
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }))
app.use('/public/', express.static('./public'));

initWebRoutes(app);
app.use("/api/user", userRouter);
app.use("/api/garden", gardenRouter);	
app.use("/api/device", deviceRouter);
app.use("/api/activityLog", LogRouter);
viewEngine(app);


app.use(
  cors({
    origin: "*",
    methods:["GET", "POST"],
  })
);

// connectDB();
global._io.on('connection',
  SocketServices.connection)

let port = process.env.PORT || 6969;


mongoose.connect(
  `mongodb+srv://linhnguyen123:linhnguyen123@cluster0.qflosao.mongodb.net/Node-API?retryWrites=true&w=majority&appName=Cluster0`
  
)
.then(() => {
  console.log('Connected to mongodb');
})
.catch((err) => console.log(err))

server.listen(port, () => {
  console.log(`Server running at: http://localhost:${port}`);
});
