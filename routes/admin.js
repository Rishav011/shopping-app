const path = require('path');

const express = require('express');

const {body} = require('express-validator/check');

const adminController = require('../controllers/admin');
const isAuth = require('../middleware/is-auth');

const router = express.Router();

// /admin/add-product => GET
// 
router.get('/add-product', isAuth, adminController.getAddProduct);

// /admin/products => GET
// Used for getting all products
router.get('/products', isAuth, adminController.getProducts);

// /admin/add-product => POST
// Used for adding new product
router.post('/add-product',[
    body('title').isString().isLength({min:5}).trim(),
    body('price').isFloat(),
    body('description').isLength({min:10}).trim()
], isAuth, adminController.postAddProduct);

router.get('/edit-product/:productId', isAuth, adminController.getEditProduct);

router.post('/edit-product',[
    body('title').isString().isLength({min:5}).trim(),
    body('price').isFloat(),
    body('description').isLength({min:10}).trim()
], isAuth, adminController.postEditProduct);

router.delete('/product/:productId', isAuth, adminController.deleteProduct);

module.exports = router;
