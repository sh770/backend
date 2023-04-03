import express from 'express';
import Product from '../models/productModel.js';


const productRouter = express.Router();

productRouter.get('/', async (req, res) => {
    const products = await Product.find();
    res.send(products);
});

productRouter.get('/:slug', async (req,res) => {
    const product = await Product.findOne({ slug: req.params.slug });
    if(product) {
        res.send(product);
    } else {
        res.status(404).send({message: 'המוצר לא נמצא'});
    }
});

productRouter.get('/product/:id', async (req,res) => {
    const product = await Product.findById(req.params.id);
    if(product) {
        res.send(product);
    } else {
        res.status(404).send({message: 'המוצר לא נמצא'});
    }
});



export default productRouter;