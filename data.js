import bcrypt from 'bcryptjs';

const data = {

  users: [
    {
      firstName: 'aa',
      lastName: 'admin',
      username: 'a_admin',
      email: 'a@gmail.com',
      password: bcrypt.hashSync('123456'),
      isAdmin: true,
    },
    {
      firstName: 'b',
      lastName: 'geeks',
      username: 'progeeks_user',
      email: 'b@gmail.com',
      password: bcrypt.hashSync('123456'),
      isAdmin: false,
    },
  ],
  products: [
    // {
    //   name: 'Nike Slim shirt',
    //   slug: 'nike-slim-shirt',
    //   category: 'Shirts',
    //   image: '/images/p1.jpg',
    //   price: 120,
    //   countInStock: 10,
    //   brand: 'Nike',
    //   rating: 4.5,
    //   numReviews: 10,
    //   description: 'a high quality nike shirt',
    // },
    // {
    //   name: 'Adidas Fit Shirt',
    //   slug: 'adidas-fit-shirt',
    //   category: 'Shirts',
    //   image: '/images/p2.jpg',
    //   price: 250,
    //   countInStock: 20,
    //   brand: 'Adidas',
    //   rating: 4.0,
    //   numReviews: 10,
    //   description: 'a high quality adidas shirt',
    // },
    // {
    //   name: 'Nike Slim Pant',
    //   slug: 'nike-slim-pant',
    //   category: 'Pants',
    //   image: '/images/p3.jpg',
    //   price: 25,
    //   countInStock: 15,
    //   brand: 'Nike',
    //   rating: 4.5,
    //   numReviews: 14,
    //   description: 'a high quality nike pants',
    // },
    // {
    //   name: 'Adidas Fit Pant',
    //   slug: 'adidas-fit-pant',
    //   category: 'Pants',
    //   image: '/images/p4.jpg',
    //   price: 65,
    //   countInStock: 5,
    //   brand: 'Puma',
    //   rating: 4.5,
    //   numReviews: 10,
    //   description: 'a high quality adidas pants',
    // },
  ],
};
export default data;