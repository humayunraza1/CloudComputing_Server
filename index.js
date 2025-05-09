const express = require('express');
const cors = require('cors');
const sql = require('mssql');
const bcrypt = require('bcryptjs');
const cookieParser = require('cookie-parser');
const { authenticate, checkRole } = require('./middleware/auth');
const { generateTokens } = require('./utils/auth');
const { dbConfig } = require('./config/database');
const { v4: uuidv4 } = require('uuid');
require('dotenv').config();
const { isAdmin } = require('./middleware/auth');
const { authenticateToken } = require('./middleware/auth');


const app = express();

// Middleware
app.use(cors({
    origin: process.env.CLIENT_URL || 'http://localhost:5173',
    credentials: true
}));
app.use(express.json());
app.use(cookieParser());

// Test database connection
async function testConnection() {
    try {
        await sql.connect(dbConfig);
        console.log('Connected to Azure SQL Database');
    } catch (err) {
        console.error('Database connection failed:', err);
    }
}

testConnection();

// Auth routes
app.post('/auth/login', async (req, res) => {
    try {
        const { identifier, password } = req.body; // 'identifier' can be email or username
        if (!identifier || !password) {
            return res.status(400).json({ error: 'Email/Username and password are required' });
        }

        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('identifier', sql.VarChar(255), identifier)
            .query('SELECT * FROM Users WHERE email = @identifier OR username = @identifier');

        if (result.recordset.length === 0) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const user = result.recordset[0];
        // Use the correct password column name
        const hash = user.password_hash || user.password;
        if (!hash) {
            return res.status(500).json({ error: 'User password not set' });
        }

        const validPassword = await bcrypt.compare(password, hash);

        if (!validPassword) {
            return res.status(401).json({ error: 'Invalid credentials' });
        }

        const tokens = generateTokens(user);

        // Set cookies
        res.cookie('accessToken', tokens.accessToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 24 * 60 * 60 * 1000 // 1 day
        });

        res.cookie('refreshToken', tokens.refreshToken, {
            httpOnly: true,
            secure: process.env.NODE_ENV === 'production',
            maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
        });

        // Return user data without sensitive information
        const { password: pw, password_hash, ...userData } = user;
        res.json(userData);
    } catch (err) {
        console.error('Login error:', err);
        res.status(500).json({ error: 'Login failed' });
    }
});

app.get('/auth/me', authenticate, async (req, res) => {
    try {
        console.log('req.user:', req.user);
        const pool = await sql.connect(dbConfig);
        const userId = req.user.id || req.user.userId;
        if (!userId) {
            return res.status(404).json({ error: 'User id not found' });
        }
        const result = await pool.request()
            .input('userId', sql.Int, userId)
            .query('SELECT id,email,username,role FROM Users WHERE id = @userId');
        if (result.recordset.length === 0) {
            return res.status(404).json({ error: 'User not found' });
        }
        const user = result.recordset[0];
        const { password_hash, ...userData } = user;
        res.json({ ...userData, id: user.id });
    } catch (err) {
        console.error('Get user error:', err);
        res.status(500).json({ error: 'Failed to get user data' });
    }
});

app.post('/auth/logout', (req, res) => {
    res.clearCookie('accessToken');
    res.clearCookie('refreshToken');
    res.json({ message: 'Logged out successfully' });
});

// Register new user
app.post('/auth/register', async (req, res) => {
    try {
        const { username, email, password } = req.body;
        if (!username || !email || !password) {
            return res.status(400).json({ error: 'Username, email, and password are required' });
        }

        const pool = await sql.connect(dbConfig);
        // Check if username or email already exists
        const existing = await pool.request()
            .input('username', sql.VarChar(255), username)
            .input('email', sql.VarChar(255), email)
            .query('SELECT * FROM Users WHERE username = @username OR email = @email');
        if (existing.recordset.length > 0) {
            return res.status(409).json({ error: 'Username or email already exists' });
        }

        // Hash password
        const password_hash = await bcrypt.hash(password, 10);

        // Insert new user
        await pool.request()
            .input('username', sql.VarChar(255), username)
            .input('email', sql.VarChar(255), email)
            .input('password_hash', sql.VarChar(255), password_hash)
            .input('role', sql.VarChar(50), 'User')
            .query('INSERT INTO Users (username, email, password, role) VALUES (@username, @email, @password_hash, @role)');

        res.status(201).json({ message: 'User registered successfully' });
    } catch (err) {
        console.error('Registration error:', err);
        res.status(500).json({ error: 'Registration failed' });
    }
});

// Basic routes
app.get('/', (req, res) => {
    res.json({ message: 'Welcome to the E-commerce API' });
});

// Products routes
// Get all products with basic info
app.get('/api/products', async (req, res) => {
    try {
        const { category, subcategory } = req.query;
        const pool = await sql.connect(dbConfig);
        
        let query = `
            SELECT 
                p.id,
                p.name, 
                p.image_url as picture, 
                p.price, 
                p.variant,
                p.quantity,
                p.stock_status,
                c.name as category,
                sc.name as subcategory
            FROM Products p
            LEFT JOIN Categories c ON p.category_id = c.id
            LEFT JOIN SubCategories sc ON p.subcategory_id = sc.id
        `;

        const request = pool.request();

        if (category) {
            query += ' WHERE p.category_id = @categoryId';
            request.input('categoryId', sql.Int, category);
        }

        if (subcategory) {
            query += category ? ' AND' : ' WHERE';
            query += ' p.subcategory_id = @subcategoryId';
            request.input('subcategoryId', sql.Int, subcategory);
        }

        const result = await request.query(query);
        res.json(result.recordset);
    } catch (err) {
        console.error('Error fetching products:', err);
        res.status(500).json({ error: err.message });
    }
});

// Get specific product with all details
app.get('/api/products/:id', async (req, res) => {
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('id', sql.Int, req.params.id)
            .query('SELECT * FROM Products WHERE product_id = @id');
        
        if (result.recordset.length === 0) {
            return res.status(404).json({ error: 'Product not found' });
        }
        
        res.json(result.recordset[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Create new product
app.post('/api/products', async (req, res) => {
    try {
        const { name, description, price, quantity, category_id, subcategory_id, variant, stock_status, image_url } = req.body;
        
        // Validate required fields
        if (!name || !price || !category_id || !subcategory_id) {
            return res.status(400).json({ error: 'Name, price, category, and subcategory are required' });
        }

        // Set stock_status based on quantity
        const calculatedStockStatus = quantity > 0 ? 'in_stock' : 'out_of_stock';

        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('name', sql.VarChar(100), name)
            .input('description', sql.Text, description)
            .input('price', sql.Decimal(10,2), price)
            .input('quantity', sql.Int, quantity || 0)
            .input('category_id', sql.Int, category_id)
            .input('subcategory_id', sql.Int, subcategory_id)
            .input('variant', sql.VarChar(50), variant || 'None')
            .input('stock_status', sql.VarChar(50), calculatedStockStatus)
            .input('image_url', sql.VarChar(255), image_url)
            .query(`
                INSERT INTO Products (name, description, price, quantity, category_id, subcategory_id, variant, stock_status, image_url)
                VALUES (@name, @description, @price, @quantity, @category_id, @subcategory_id, @variant, @stock_status, @image_url);
                SELECT SCOPE_IDENTITY() AS id;
            `);

        const newProductId = result.recordset[0].id;
        
        // Fetch the newly created product with category and subcategory names
        const newProduct = await pool.request()
            .input('id', sql.Int, newProductId)
            .query(`
                SELECT 
                    p.*,
                    c.name as category,
                    sc.name as subcategory
                FROM Products p
                LEFT JOIN Categories c ON p.category_id = c.id
                LEFT JOIN SubCategories sc ON p.subcategory_id = sc.id
                WHERE p.id = @id
            `);

        res.status(201).json(newProduct.recordset[0]);
    } catch (err) {
        console.error('Error creating product:', err);
        res.status(500).json({ error: err.message });
    }
});

// Order tracking (public route)
app.get('/api/trackorder/:id', async (req, res) => {
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('id', sql.Int, req.params.id)
            .query(`
                SELECT 
                    order_id,
                    destination_city,
                    order_date,
                    status,
                    tracking_number,
                    estimated_delivery
                FROM Orders 
                WHERE order_id = @id
            `);
        
        if (result.recordset.length === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }
        
        res.json(result.recordset[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get all orders (Admin/Editor only)
app.get('/api/orders', authenticate, checkRole(['Admin', 'Editor']), async (req, res) => {
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .query(`
                SELECT 
                    o.order_id,
                    o.order_date,
                    o.total_amount,
                    o.status,
                    o.destination_city,
                    o.payment_status,
                    o.tracking_number,
                    o.estimated_delivery,
                    u.username,
                    u.email,
                    (
                        SELECT STRING_AGG(
                            CONCAT(p.name, ' (', oi.quantity, ')'),
                            ', '
                        )
                        FROM OrderItems oi
                        JOIN Products p ON oi.product_id = p.product_id
                        WHERE oi.order_id = o.order_id
                    ) as order_items
                FROM Orders o
                JOIN Users u ON o.user_id = u.user_id
                ORDER BY o.order_date DESC
            `);
        
        res.json(result.recordset);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Get specific order details (Admin/Editor only)
app.get('/api/orders/:id', authenticate, checkRole(['Admin', 'Editor']), async (req, res) => {
    try {
        const pool = await sql.connect(dbConfig);
        const result = await pool.request()
            .input('id', sql.Int, req.params.id)
            .query(`
                SELECT 
                    o.*,
                    u.username,
                    u.email,
                    u.phone,
                    u.address as user_address,
                    (
                        SELECT JSON_QUERY((
                            SELECT 
                                oi.order_item_id,
                                p.name,
                                p.description,
                                oi.quantity,
                                oi.unit_price,
                                (oi.quantity * oi.unit_price) as total_price
                            FROM OrderItems oi
                            JOIN Products p ON oi.product_id = p.product_id
                            WHERE oi.order_id = o.order_id
                            FOR JSON PATH
                        ))
                    ) as order_items
                FROM Orders o
                JOIN Users u ON o.user_id = u.user_id
                WHERE o.order_id = @id
            `);
        
        if (result.recordset.length === 0) {
            return res.status(404).json({ error: 'Order not found' });
        }
        
        res.json(result.recordset[0]);
    } catch (err) {
        res.status(500).json({ error: err.message });
    }
});

// Update order status (admin only)
app.put('/api/admin/orders/:id/status', authenticate, checkRole(['Admin', 'moderator']), async (req, res) => {
  const { id } = req.params;
  const { status } = req.body;

  // Validate status
  const validStatuses = ['pending', 'accepted', 'shipped', 'delivered', 'cancelled'];
  if (!validStatuses.includes(status)) {
    return res.status(400).json({ error: 'Invalid status' });
  }

  try {
    const pool = await sql.connect(dbConfig);
    const transaction = new sql.Transaction(pool);
    await transaction.begin();

    try {
      // If status is being changed to cancelled, we need to update product quantities
      if (status === 'cancelled') {
        // Get the order items
        const orderItems = await new sql.Request(transaction)
          .input('orderId', sql.Int, id)
          .query(`
            SELECT oi.product_id, oi.quantity
            FROM OrderItems oi
            WHERE oi.order_id = @orderId
          `);

        // Update each product's quantity and stock status
        for (const item of orderItems.recordset) {
          await new sql.Request(transaction)
            .input('productId', sql.Int, item.product_id)
            .input('quantity', sql.Int, item.quantity)
            .query(`
              UPDATE Products
              SET 
                quantity = quantity + @quantity,
                stock_status = CASE 
                  WHEN quantity + @quantity > 0 THEN 'in_stock'
                  ELSE 'out_of_stock'
                END
              WHERE id = @productId
            `);
        }
      }

      // Update the order status
      const result = await new sql.Request(transaction)
        .input('id', sql.Int, id)
        .input('status', sql.VarChar(20), status)
        .query(`
          UPDATE Orders 
          SET status = @status 
          WHERE id = @id;
          
          SELECT * FROM Orders WHERE id = @id;
        `);

      if (result.recordset.length === 0) {
        await transaction.rollback();
        return res.status(404).json({ error: 'Order not found' });
      }

      await transaction.commit();
      res.json(result.recordset[0]);
    } catch (error) {
      await transaction.rollback();
      throw error;
    }
  } catch (error) {
    console.error('Error updating order status:', error);
    res.status(500).json({ error: 'Failed to update order status' });
  }
});

// Get all categories with their subcategories
app.get('/api/categories', async (req, res) => {
  try {
    const pool = await sql.connect(dbConfig);
    const result = await pool.request()
      .query(`
        SELECT 
          c.id,
          c.name,
          (
            SELECT sc.id, sc.name
            FROM SubCategories sc
            WHERE sc.category_id = c.id
            FOR JSON PATH
          ) as subcategories
        FROM Categories c
        ORDER BY c.name
      `);

    const categories = result.recordset.map(category => ({
      ...category,
      subcategories: category.subcategories ? JSON.parse(category.subcategories) : []
    }));

    res.json(categories);
  } catch (error) {
    console.error('Error fetching categories:', error);
    res.status(500).json({ error: 'Failed to fetch categories' });
  }
});

// Create new category
app.post('/api/categories', async (req, res) => {
  try {
    const { name } = req.body;

    if (!name) {
      return res.status(400).json({ error: 'Category name is required' });
    }

    const pool = await sql.connect(dbConfig);
    const result = await pool.request()
      .input('name', sql.VarChar(255), name)
      .query(`
        INSERT INTO Categories (name)
        VALUES (@name);
        SELECT SCOPE_IDENTITY() AS id;
      `);

    const newCategoryId = result.recordset[0].id;

    // Fetch the newly created category
    const newCategory = await pool.request()
      .input('id', sql.Int, newCategoryId)
      .query('SELECT * FROM Categories WHERE id = @id');

    res.status(201).json({
      ...newCategory.recordset[0],
      subcategories: []
    });
  } catch (error) {
    console.log('Error creating category:', error);
    res.status(500).json({ error: 'Failed to create category' });
  }
});

// Create new subcategory
app.post('/api/categories/:categoryId/subcategories', async (req, res) => {
  try {
    const { name } = req.body;
    const { categoryId } = req.params;

    if (!name) {
      return res.status(400).json({ error: 'Subcategory name is required' });
    }

    // First check if the parent category exists
    const pool = await sql.connect(dbConfig);
    const categoryCheck = await pool.request()
      .input('categoryId', sql.Int, categoryId)
      .query('SELECT id FROM Categories WHERE id = @categoryId');

    if (categoryCheck.recordset.length === 0) {
      return res.status(404).json({ error: 'Parent category not found' });
    }

    // Create the subcategory
    const result = await pool.request()
      .input('categoryId', sql.Int, categoryId)
      .input('name', sql.VarChar(255), name)
      .query(`
        INSERT INTO SubCategories (category_id, name)
        VALUES (@categoryId, @name);
        SELECT SCOPE_IDENTITY() AS id;
      `);

    const newSubcategoryId = result.recordset[0].id;

    // Fetch the newly created subcategory
    const newSubcategory = await pool.request()
      .input('id', sql.Int, newSubcategoryId)
      .query('SELECT * FROM SubCategories WHERE id = @id');

    res.status(201).json(newSubcategory.recordset[0]);
  } catch (error) {
    console.log('Error creating subcategory:', error);
    res.status(500).json({ error: 'Failed to create subcategory' });
  }
});

// Place a new order
app.post('/api/orders', async (req, res) => {
  try {
    const { name, address, phone, user_id, total_amount, items } = req.body;
    if (!name || !address || !phone || !total_amount || !Array.isArray(items) || items.length === 0) {
      return res.status(400).json({ error: 'Missing required order fields' });
    }

    // Generate tracking_id as userId-YYYYMMDDHHmmss
    const now = new Date();
    const pad = n => n.toString().padStart(2, '0');
    const dateTime =
      now.getFullYear().toString() +
      pad(now.getMonth() + 1) +
      pad(now.getDate()) +
      pad(now.getHours()) +
      pad(now.getMinutes()) +
      pad(now.getSeconds());
    const tracking_id = `${user_id || 'guest'}-${dateTime}`;

    const pool = await sql.connect(dbConfig);
    
    // Create a transaction to ensure data consistency
    const transaction = new sql.Transaction(pool);
    await transaction.begin();
    
    try {
      // First, check if all products have enough stock
      for (const item of items) {
        const stockCheck = await new sql.Request(transaction)
          .input('id', sql.Int, item.product_id)
          .query(`
            SELECT quantity, name FROM Products 
            WHERE id = @id
          `);
        
        if (stockCheck.recordset.length === 0) {
          throw new Error(`Product with ID ${item.product_id} not found`);
        }
        
        const product = stockCheck.recordset[0];
        if (product.quantity < item.quantity) {
          throw new Error(`Not enough stock for ${product.name}. Available: ${product.quantity}, Requested: ${item.quantity}`);
        }
      }
      
      // Insert order
      const orderResult = await new sql.Request(transaction)
        .input('user_id', sql.Int, user_id)
        .input('total_amount', sql.Decimal(10,2), total_amount)
        .input('status', sql.VarChar(50), 'pending')
        .input('name', sql.VarChar(255), name)
        .input('address', sql.VarChar(255), address)
        .input('phone', sql.VarChar(50), phone)
        .input('tracking_id', sql.VarChar(100), tracking_id)
        .query(`
          INSERT INTO Orders (user_id, total_amount, status, name, address, phone, tracking_id)
          VALUES (@user_id, @total_amount, @status, @name, @address, @phone, @tracking_id);
          SELECT SCOPE_IDENTITY() AS order_id;
        `);
      const order_id = orderResult.recordset[0].order_id;

      // Insert order items and update stock quantity
      for (const item of items) {
        // Insert order item
        await new sql.Request(transaction)
          .input('order_id', sql.Int, order_id)
          .input('product_id', sql.Int, item.product_id)
          .input('quantity', sql.Int, item.quantity)
          .input('price', sql.Decimal(10,2), item.price)
          .query(`
            INSERT INTO OrderItems (order_id, product_id, quantity, price)
            VALUES (@order_id, @product_id, @quantity, @price)
          `);
        
        // Get current quantity to check if it will become zero
        const currentStockResult = await new sql.Request(transaction)
          .input('id', sql.Int, item.product_id)
          .query(`
            SELECT quantity FROM Products 
            WHERE id = @id
          `);
        
        const currentQuantity = currentStockResult.recordset[0].quantity;
        const newQuantity = currentQuantity - item.quantity;
        
        // Decrease stock quantity and update stock_status if needed
        await new sql.Request(transaction)
          .input('id', sql.Int, item.product_id)
          .input('quantity', sql.Int, item.quantity)
          .input('stock_status', sql.VarChar(50), newQuantity <= 0 ? 'out_of_stock' : 'in_stock')
          .query(`
            UPDATE Products
            SET 
              quantity = quantity - @quantity,
              stock_status = @stock_status
            WHERE id = @id
          `);
      }
      
      // Commit the transaction
      await transaction.commit();
      
      res.status(201).json({ message: 'Order placed successfully', order_id, tracking_id });
    } catch (err) {
      // Rollback transaction if there's an error
      await transaction.rollback();
      throw err; // Re-throw to be caught by the outer catch
    }
  } catch (err) {
    console.error('Order placement error:', err);
    
    // Return a more specific error message to the client
    if (err.message && err.message.includes('Not enough stock')) {
      return res.status(400).json({ error: err.message });
    }
    
    res.status(500).json({ error: 'Failed to place order' });
  }
});

// Get all orders for the logged-in user
app.get('/api/user/orders', authenticate, async (req, res) => {
  try {
    const userId = req.user.id || req.user.userId;
    if (!userId) {
      return res.status(401).json({ error: 'User not authenticated' });
    }
    const pool = await sql.connect(dbConfig);
    // Get all orders for this user
    const ordersResult = await pool.request()
      .input('userId', sql.Int, userId)
      .query(`
        SELECT id, created_at, status, total_amount, tracking_id
        FROM Orders
        WHERE user_id = @userId
        ORDER BY created_at DESC
      `);
    const orders = ordersResult.recordset;
    // For each order, get its items
    for (const order of orders) {
      const itemsResult = await pool.request()
        .input('orderId', sql.Int, order.id)
        .query(`
          SELECT oi.id, p.name, oi.quantity, oi.price
          FROM OrderItems oi
          JOIN Products p ON oi.product_id = p.id
          WHERE oi.order_id = @orderId
        `);
      order.items = itemsResult.recordset;
    }
    res.json(orders);
  } catch (err) {
    console.error('Error fetching user orders:', err);
    res.status(500).json({ error: 'Failed to fetch user orders' });
  }
});

// Get all orders (admin only)
app.get('/api/admin/orders', authenticate, checkRole(['Admin', 'moderator']), async (req, res) => {
  try {
    const pool = await sql.connect(dbConfig);
    const orders = await pool.request()
      .query(`
        SELECT o.*, u.email as user_email
        FROM Orders o
        LEFT JOIN Users u ON o.user_id = u.id
        ORDER BY o.created_at DESC
      `);
    
    // Get order items for each order
    const ordersWithItems = await Promise.all(orders.recordset.map(async (order) => {
      const items = await pool.request()
        .input('orderId', sql.Int, order.id)
        .query(`
          SELECT 
            oi.id,
            oi.order_id,
            oi.product_id,
            oi.quantity,
            oi.price,
            p.name,
            p.created_at
          FROM OrderItems oi
          JOIN Products p ON oi.product_id = p.id
          WHERE oi.order_id = @orderId
        `);
      
      return {
        ...order,
        items: items.recordset,
        user: { email: order.user_email }
      };
    }));

    res.json(ordersWithItems);
  } catch (error) {
    console.error('Error fetching orders:', error);
    res.status(500).json({ error: 'Failed to fetch orders' });
  }
});

// Start server
const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
    console.log(`Server is running on port ${PORT}`);
}); 