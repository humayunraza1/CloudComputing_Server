-- Drop tables if they exist (in reverse order of dependencies)
IF OBJECT_ID('OrderItems', 'U') IS NOT NULL
    DROP TABLE OrderItems;

IF OBJECT_ID('Orders', 'U') IS NOT NULL
    DROP TABLE Orders;

IF OBJECT_ID('Products', 'U') IS NOT NULL
    DROP TABLE Products;

IF OBJECT_ID('SubCategories', 'U') IS NOT NULL
    DROP TABLE SubCategories;

IF OBJECT_ID('Categories', 'U') IS NOT NULL
    DROP TABLE Categories;

IF OBJECT_ID('Users', 'U') IS NOT NULL
    DROP TABLE Users;

-- Create Users table
CREATE TABLE Users (
    id INT IDENTITY(1,1) PRIMARY KEY,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    role VARCHAR(50) NOT NULL DEFAULT 'user',
    created_at DATETIME DEFAULT GETDATE(),
    updated_at DATETIME DEFAULT GETDATE()
);

-- Create Categories table
CREATE TABLE Categories (
    id INT IDENTITY(1,1) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT GETDATE(),
    updated_at DATETIME DEFAULT GETDATE()
);

-- Create SubCategories table
CREATE TABLE SubCategories (
    id INT IDENTITY(1,1) PRIMARY KEY,
    category_id INT NOT NULL REFERENCES Categories(id),
    name VARCHAR(255) NOT NULL,
    created_at DATETIME DEFAULT GETDATE(),
    updated_at DATETIME DEFAULT GETDATE()
);

-- Create Products table
CREATE TABLE Products (
    id INT IDENTITY(1,1) PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    description TEXT,
    variant VARCHAR(255) DEFAULT 'None',
    price DECIMAL(10,2) NOT NULL,
    quantity INT NOT NULL DEFAULT 0,
    category_id INT NOT NULL REFERENCES Categories(id),
    subcategory_id INT NOT NULL REFERENCES SubCategories(id),
    stock_status VARCHAR(50) NOT NULL DEFAULT 'in_stock',
    image_url VARCHAR(255),
    created_at DATETIME DEFAULT GETDATE(),
    updated_at DATETIME DEFAULT GETDATE()
);

-- Create Orders table
CREATE TABLE Orders (
    id INT IDENTITY(1,1) PRIMARY KEY,
    user_id INT NOT NULL REFERENCES Users(id),
    total_amount DECIMAL(10,2) NOT NULL,
    status VARCHAR(50) NOT NULL DEFAULT 'pending',
    created_at DATETIME DEFAULT GETDATE(),
    updated_at DATETIME DEFAULT GETDATE()
);

-- Create OrderItems table
CREATE TABLE OrderItems (
    id INT IDENTITY(1,1) PRIMARY KEY,
    order_id INT NOT NULL REFERENCES Orders(id),
    product_id INT NOT NULL REFERENCES Products(id),
    quantity INT NOT NULL,
    price DECIMAL(10,2) NOT NULL,
    created_at DATETIME DEFAULT GETDATE()
);
-- Create trigger to update product quantities after order placement

