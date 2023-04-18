import express from "express";
// import data from "./data.js";
import mongoose from "mongoose";
import dotenv from "dotenv";
import productRouter from "./routes/productRoutes.js";
import seedRouter from "./routes/seedRoutes.js";
import userRouter from "./routes/userRoutes.js";



dotenv.config();

mongoose
    .connect(process.env.MONGODB_URI, { useNewUrlParser: true, useUnifiedTopology: true })

    .then(() => {
        console.log('connected to db');
    })
    .catch((err) => {
        console.log(err.message);
    });

const app = express();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use('/api/products', productRouter);
app.use('/api/seed', seedRouter);
app.use('/api/users', userRouter);

app.use((err, req, res, next)=>{
    res.status(500).send({ message: err.message});
})



// app.get('/api/products', (req, res) => {
//         res.send(data.products); 
// });

// app.get('/api/products/:slug', (req, res) => {
//     const product = data.products.find((x) => x.slug == req.params.slug);
//     if (product) {
//         res.send(product);
//     } else {
//         res.status(404).send({ message: 'המוצר לא נמצא' });
//     }
// });

// app.get('/api/product/:id', (req,res) => {
//     const product = data.products.find((x) => x._id === req.params.id);
//     if(product) {
//         res.send(product);
//     } else {
//         res.status(404).send({ message: 'המוצר לא נמצא' });
//     }
// });

const port = process.env.PORT || 5000;
app.listen(port, () => {
    console.log(`server running on http://localhost:${port}`);
});