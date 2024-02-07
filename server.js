import express from "express";
import mysql from "mysql";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from 'dotenv';
dotenv.config();

const jsonParser = bodyParser.json();
const saltRounds = 10;
const secret = process.env.SECRET_KEY;
const app = express();
app.use(cors());
app.use(express.json());

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password:process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

app.post("/register", jsonParser, function (req, res, next) {
  const minUsernameLength = 5;
  const maxUsernameLength = 20;
  const minPasswordLength = 8;
  const maxPasswordLength = 30;
  if (
    !req.body.username ||
    req.body.username.length < minUsernameLength ||
    req.body.username.length > maxUsernameLength
  ) {
    return res.json({
      status: "error",
      message: `Username must be between ${minUsernameLength} and ${maxUsernameLength} characters.`,
    });
  }
  if (
    !req.body.password ||
    req.body.password.length < minPasswordLength ||
    req.body.password.length > maxPasswordLength
  ) {
    return res.json({
      status: "error",
      message: `Password must be between ${minPasswordLength} and ${maxPasswordLength} characters.`,
    });
  }
  checkUsernameExists(req.body.username, function (usernameExists) {
    if (usernameExists) {
      return res.json({
        status: "error",
        message: "Username already exists.",
      });
    }
    bcrypt.hash(req.body.password, saltRounds, function (err, hash) {
      if (err) {
        return res.json({ status: "error", message: err });
      }
      db.query(
        "INSERT INTO users (username, password) VALUES (?, ?)",
        [req.body.username, hash],
        function (err, results, fields) {
          if (err) {
            return res.json({ status: "error", message: err });
          }
          return res.json({ status: "ok" });
        }
      );
    });
  });
});
function checkUsernameExists(username, callback) {
  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    function (err, results, fields) {
      if (err) {
        return callback(false); 
      }
      callback(results.length > 0);
    }
  );
}

app.post("/login", jsonParser, function (req, res, next) {
  db.query(
    "SELECT * FROM users WHERE username = ?",
    [req.body.username],
    function (err, users, fields) {
      if (err) {
        res.json({ status: "error", message: err });
        return;
      }
      if (users.length == 0) {
        res.json({ status: "error", message: "no user found" });
        return;
      }
      bcrypt.compare(
        req.body.password,
        users[0].password,
        function (err, isLogin) {
          if (isLogin) {
            var token = jwt.sign({ username: users[0].username }, secret, { expiresIn: '5h' });
            res.json({ status: "ok", message: "Login success", token });
          } else {
            res.json({ status: "error", message: "Login failed" });
          }
        }
      );
    }
  );
});

app.post("/authen", jsonParser, function (req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    var decoded = jwt.verify(token, secret);
    res.json({ status: "ok", decoded });
  } catch (err) {
    res.json({ status: "error", message: err.message });
  }
});

app.post('/check-username', (req, res) => {
  const { username } = req.body;
  db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
    if (err) {
      console.error(err);
      res.status(500).json({ error: 'Database error', details: err.message });
    } else {
      const user = results[0];
      if (user) {
        res.json({ usernameExists: true, userId: user.id });
      } else {
        res.json({ usernameExists: false });
      }
    }
  });
});

app.put("/users/:id/reset-password", async (req, res) => {
  const id = req.params.id;
  const newPassword = req.body.newPassword;
  try {
    if (newPassword.length < 8 || newPassword.length > 30) {
      return res.status(400).json({ status: "error", message: "Password must be between 8 and 30 characters long" });
    }
    const hash = await bcrypt.hash(newPassword, saltRounds);
    db.query(
      "UPDATE users SET `password`=? WHERE id=?",
      [hash, id],
      function (err, results, fields) {
        if (err) {
          console.error("Error updating password in the database:", err);
          return res.status(500).json({ status: "error", message: "Error updating password in the database" });
        }
        return res.json({ status: "ok" });
      }
    );
  } catch (error) {
    console.error("Error hashing password:", error);
    return res.status(500).json({ status: "error", message: "Error hashing password" });
  }
});

// CRUD API
//API FOR hw-asset
app.get("/hw-asset", (req, res) => {
  const sql = "SELECT *  FROM hw_asset";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

app.post("/addhw-asset", (req, res) => {
  const requiredFields = [
    'assetnum', 'brand', 'model', 'user', 'location', 'spec',
    'sn', 'software', 'price', 'receivedate', 'invoicenum', 'ponum'
  ];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  for (const field in req.body) {
    if (req.body.hasOwnProperty(field) && req.body[field] === null) {
      return res.status(400).json({ Message: `${field} cannot be null.` });
    }
  }
  const sql =
    "INSERT INTO hw_asset (`assetnum`, `brand`, `model`, `user`, `location`, `spec`, `sn`, `software`, `price`, `receivedate`, `invoicenum`, `ponum`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  const values = [
    req.body.assetnum,
    req.body.brand,
    req.body.model,
    req.body.user,
    req.body.location,
    req.body.spec,
    req.body.sn,
    req.body.software,
    req.body.price,
    req.body.receivedate,
    req.body.invoicenum,
    req.body.ponum,
  ];
  db.query(sql, values, (err, result) => {
    if (err) return res.json(err);
    return res.json(result);
  });
});

app.get("/readhw-asset/:id", (req, res) => {
  const sql = "SELECT * FROM hw_asset WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

app.put("/updatehw-asset/:id", (req, res) => {
  const requiredFields = [
    'assetnum', 'brand', 'model', 'user', 'location', 'spec',
    'sn', 'software', 'price', 'receivedate', 'invoicenum', 'ponum'
  ];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  for (const field in req.body) {
    if (req.body.hasOwnProperty(field) && req.body[field] === null) {
      return res.status(400).json({ Message: `${field} cannot be null.` });
    }
  }
  const sql =
    "UPDATE hw_asset SET `assetnum`=?, `brand`=?, `model`=?, `user`=?, `location`=?, `spec`=?, `sn`=?, `software`=?, `price`=?, `receivedate`=?, `invoicenum`=?, `ponum`=? WHERE id=?";
  const id = req.params.id;
  db.query(
    sql,
    [
      req.body.assetnum,
      req.body.brand,
      req.body.model,
      req.body.user,
      req.body.location,
      req.body.spec,
      req.body.sn,
      req.body.software,
      req.body.price,
      req.body.receivedate,
      req.body.invoicenum,
      req.body.ponum,
      id,
    ],
    (err, result) => {
      if (err) return res.status(500).json({ Message: "Error inside server" });
      return res.json(result);
    }
  );
});

app.delete("/deletehw-asset/:id", (req, res) => {
  const sql = "DELETE FROM hw_asset WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//API FOR hw-asset

//API FOR hw_accessories
app.get("/hw-accessories", (req, res) => {
  const sql = "SELECT * FROM hw_accessories";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

app.post("/addhw-accessories", (req, res) => {
  const requiredFields = [
    `type`, `detail`, `sn`, `assetinstall`, `location`, `price`, `receivedate`, `invoicenum`, `ponum`
  ];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  for (const field in req.body) {
    if (req.body.hasOwnProperty(field) && req.body[field] === null) {
      return res.status(400).json({ Message: `${field} cannot be null.` });
    }
  }
  const sql =
    "INSERT INTO hw_accessories (`type`, `detail`, `sn`, `assetinstall`, `location`, `price`, `receivedate`, `invoicenum`, `ponum`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
  const values = [
    req.body.type,
    req.body.detail,
    req.body.sn,
    req.body.assetinstall,
    req.body.location,
    req.body.price,
    req.body.receivedate,
    req.body.invoicenum,
    req.body.ponum
  ];
  db.query(sql, values, (err, result) => {
    if (err) return res.json(err);
    return res.json(result);
  });
});

app.get("/readhw-accessories/:id", (req, res) => {
  const sql = "SELECT * FROM hw_accessories WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

app.put("/updatehw-accessories/:id", (req, res) => {
  const requiredFields = [
    `type`, `detail`, `sn`, `assetinstall`, `location`, `price`, `receivedate`, `invoicenum`, `ponum`
  ];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  for (const field in req.body) {
    if (req.body.hasOwnProperty(field) && req.body[field] === null) {
      return res.status(400).json({ Message: `${field} cannot be null.` });
    }
  }
  const sql =
    "UPDATE hw_accessories SET `type`=?, `detail`=?, `sn`=?, `assetinstall`=?, `location`=?, `price`=?, `receivedate`=?, `invoicenum`=?, `ponum`=? WHERE id=?";
  const id = req.params.id;
  db.query(
    sql,
    [
        req.body.type,
        req.body.detail,
        req.body.sn,
        req.body.assetinstall,
        req.body.location,
        req.body.price,
        req.body.receivedate,
        req.body.invoicenum,
        req.body.ponum,
      id,
    ],
    (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    }
  );
});

app.delete("/deletehw-accessories/:id", (req, res) => {
  const sql = "DELETE FROM hw_accessories WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//API FOR hw_accessories

//API FOR sw_asset
app.get("/sw-asset", (req, res) => {
    const sql = "SELECT * FROM sw_asset";
    db.query(sql, (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    });
  });
  
  app.post("/addsw-asset", (req, res) => {
    const requiredFields = [
      `assetnum`, `name`, `swkey`, `user`, `assetinstall`, `location`, `price`, `receivedate`, `invoicenum`, `ponum`
    ];
    for (const field of requiredFields) {
      if (req.body[field] === undefined || req.body[field] === null) {
        return res.status(400).json({ Message: `${field} is required.` });
      }
    }
    for (const field in req.body) {
      if (req.body.hasOwnProperty(field) && req.body[field] === null) {
        return res.status(400).json({ Message: `${field} cannot be null.` });
      }
    }
    const sql =
      "INSERT INTO sw_asset (`assetnum`, `name`, `swkey`, `user`, `assetinstall`, `location`, `price`, `receivedate`, `invoicenum`, `ponum`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
    const values = [
      req.body.assetnum,
      req.body.name,
      req.body.swkey,
      req.body.user,
      req.body.assetinstall,
      req.body.location,
      req.body.price,
      req.body.receivedate,
      req.body.invoicenum,
      req.body.ponum
    ];
    db.query(sql, values, (err, result) => {
      if (err) return res.json(err);
      return res.json(result);
    });
  });
  
  app.get("/readsw-asset/:id", (req, res) => {
    const sql = "SELECT * FROM sw_asset WHERE id = ?";
    const id = req.params.id;
  
    db.query(sql, [id], (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    });
  });
  
  app.put("/updatesw-asset/:id", (req, res) => {
    const requiredFields = [
      `assetnum`, `name`, `swkey`, `user`, `assetinstall`, `location`, `price`, `receivedate`, `invoicenum`, `ponum`
    ];
    for (const field of requiredFields) {
      if (req.body[field] === undefined || req.body[field] === null) {
        return res.status(400).json({ Message: `${field} is required.` });
      }
    }
    for (const field in req.body) {
      if (req.body.hasOwnProperty(field) && req.body[field] === null) {
        return res.status(400).json({ Message: `${field} cannot be null.` });
      }
    }
    const sql =
      "UPDATE sw_asset SET `assetnum`=?, `name`=?, `swkey`=?, `user`=?, `assetinstall`=?, `location`=?, `price`=?, `receivedate`=?, `invoicenum`=?, `ponum`=? WHERE id=?";
    const id = req.params.id;
    db.query(
      sql,
      [
        req.body.assetnum,
        req.body.name,
        req.body.swkey,
        req.body.user,
        req.body.assetinstall,
        req.body.location,
        req.body.price,
        req.body.receivedate,
        req.body.invoicenum,
        req.body.ponum,
        id,
      ],
      (err, result) => {
        if (err) return res.json({ Message: "Error inside server" });
        return res.json(result);
      }
    );
  });
  
  app.delete("/deletesw-asset/:id", (req, res) => {
    const sql = "DELETE FROM sw_asset WHERE id = ?";
    const id = req.params.id;
  
    db.query(sql, [id], (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    });
  });
//API FOR sw_asset

//API FOR sw_yearly
app.get("/sw-yearly", (req, res) => {
    const sql = "SELECT * FROM sw_yearly";
    db.query(sql, (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    });
  });
  
  app.post("/addsw-yearly", (req, res) => {
    const requiredFields = [
      'name', 'assetinstall', 'expiredate', 'price', 'receivedate', 'invoicenum', 'ponum'
    ];
    for (const field of requiredFields) {
      if (req.body[field] === undefined || req.body[field] === null) {
        return res.status(400).json({ Message: `${field} is required.` });
      }
    }
    for (const field in req.body) {
      if (req.body.hasOwnProperty(field) && req.body[field] === null) {
        return res.status(400).json({ Message: `${field} cannot be null.` });
      }
    }
    const sql =
      "INSERT INTO sw_yearly (`name`, `assetinstall`, `expiredate`, `price`, `receivedate`, `invoicenum`, `ponum`) VALUES (?, ?, ?, ?, ?, ?, ?)";
    const values = [
      req.body.name,
      req.body.assetinstall,
      req.body.expiredate,
      req.body.price,
      req.body.receivedate,
      req.body.invoicenum,
      req.body.ponum
    ];
    db.query(sql, values, (err, result) => {
      if (err) return res.json(err);
      return res.json(result);
    });
  });
  
  app.get("/readsw-yearly/:id", (req, res) => {
    const sql = "SELECT * FROM sw_yearly WHERE id = ?";
    const id = req.params.id;
  
    db.query(sql, [id], (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    });
  });
  
  app.put("/updatesw-yearly/:id", (req, res) => {
    const requiredFields = [
      `name`, `assetinstall`, `expiredate`, `price`, `receivedate`, `invoicenum`, `ponum`
    ];
    for (const field of requiredFields) {
      if (req.body[field] === undefined || req.body[field] === null) {
        return res.status(400).json({ Message: `${field} is required.` });
      }
    }
    for (const field in req.body) {
      if (req.body.hasOwnProperty(field) && req.body[field] === null) {
        return res.status(400).json({ Message: `${field} cannot be null.` });
      }
    }
    const sql =
      "UPDATE sw_yearly SET `name`=?, `assetinstall`=?, `expiredate`=?, `price`=?, `receivedate`=?, `invoicenum`=?, `ponum`=? WHERE id=?";
    const id = req.params.id;
    db.query(
      sql,
      [
        req.body.name,
        req.body.assetinstall,
        req.body.expiredate,
        req.body.price,
        req.body.receivedate,
        req.body.invoicenum,
        req.body.ponum,
        id,
      ],
      (err, result) => {
        if (err) return res.json({ Message: "Error inside server" });
        return res.json(result);
      }
    );
  });
  
  app.delete("/deletesw-yearly/:id", (req, res) => {
    const sql = "DELETE FROM sw_yearly WHERE id = ?";
    const id = req.params.id;
  
    db.query(sql, [id], (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    });
  });
//API FOR sw_yearly

//API for Amortized
//Move
app.post("/movetohw-amortized/:id", (req, res) => {
  const sql = "INSERT INTO hw_amortized (`assetnum`, `brand`, `model`, `user`, `location`, `spec`, `sn`, `software`, `price`, `receivedate`, `invoicenum`, `ponum`, `amortizeddate`) SELECT assetnum, brand, model, user, location, spec, sn, software, price, receivedate, invoicenum, ponum, CURRENT_TIMESTAMP() FROM hw_asset WHERE id = ?";
  const sqldel = "DELETE FROM hw_asset WHERE id = ?";
  const id = req.params.id;
  db.query(sql, [id], (err, result) => {
    if (err) return res.json(err);
    db.query(sqldel,[id],(err, result) => {
      if (err) return res.json(err);
    })
    return res.json(result);
  });
});

app.get("/hw-amortized", (req, res) => {
  const sql = "SELECT * FROM hw_amortized";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

app.post("/addhw-amortized", (req, res) => {
  const requiredFields = [
    `assetnum`, `brand`, `model`, `user`, `location`, `spec`, `sn`, `software`, `price`, `receivedate`, `invoicenum`, `ponum`, `amortizeddate`
  ];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  for (const field in req.body) {
    if (req.body.hasOwnProperty(field) && req.body[field] === null) {
      return res.status(400).json({ Message: `${field} cannot be null.` });
    }
  }
  const sql =
    "INSERT INTO hw_amortized (`assetnum`, `brand`, `model`, `user`, `location`, `spec`, `sn`, `software`, `price`, `receivedate`, `invoicenum`, `ponum`, `amortizeddate`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  const values = [
    req.body.assetnum,
    req.body.brand,
    req.body.model,
    req.body.user,
    req.body.location,
    req.body.spec,
    req.body.sn,
    req.body.software,
    req.body.price,
    req.body.receivedate,
    req.body.invoicenum,
    req.body.ponum,
    req.body.amortizeddate,
  ];
  db.query(sql, values, (err, result) => {
    if (err) return res.json(err);
    return res.json(result);
  });
});

app.get("/readhw-amortized/:id", (req, res) => {
  const sql = "SELECT * FROM hw_amortized WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

app.put("/updatehw-amortized/:id", (req, res) => {
  const requiredFields = [
    `assetnum`, `brand`, `model`, `user`, `location`, `spec`, `sn`, `software`, `price`, `receivedate`, `invoicenum`, `ponum`, `amortizeddate`
  ];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  for (const field in req.body) {
    if (req.body.hasOwnProperty(field) && req.body[field] === null) {
      return res.status(400).json({ Message: `${field} cannot be null.` });
    }
  }
  const sql =
    "UPDATE hw_amortized SET `assetnum`=?, `brand`=?, `model`=?, `user`=?, `location`=?, `spec`=?, `sn`=?, `software`=?, `price`=?, `receivedate`=?, `invoicenum`=?, `ponum`=?, `amortizeddate`=? WHERE id=?";
  const id = req.params.id;
  db.query(
    sql,
    [
      req.body.assetnum,
      req.body.brand,
      req.body.model,
      req.body.user,
      req.body.location,
      req.body.spec,
      req.body.sn,
      req.body.software,
      req.body.price,
      req.body.receivedate,
      req.body.invoicenum,
      req.body.ponum,
      req.body.amortizeddate,
      id,
    ],
    (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    }
  );
});

app.delete("/deletehw-amortized/:id", (req, res) => {
  const sql = "DELETE FROM hw_amortized WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//API for hw-amortized
// CRUD API

//API FOR dashboard
//Get total
app.get("/hwtotal", (req, res) => {
  const sql = "SELECT COUNT(id) AS hw_asset FROM hw_asset";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

app.get("/accstotal", (req, res) => {
  const sql = "SELECT COUNT(id) AS hw_accessories	 FROM hw_accessories";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

app.get("/swtotal", (req, res) => {
  const sql = "SELECT COUNT(id) AS sw_asset FROM sw_asset";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

app.get("/swyeartotal", (req, res) => {
  const sql = "SELECT COUNT(id) AS sw_yearly FROM sw_yearly";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

app.get("/amortizedtotal", (req, res) => {
  const sql = "SELECT COUNT(id) AS hw_amortized FROM hw_amortized";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

//Get sum price
app.get("/hwtotalprice", (req, res) => {
  const sql = "SELECT sum(price) AS price FROM hw_asset";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result[0]); 
  });
});

app.get("/accstotalprice", (req, res) => {
  const sql = "SELECT sum(price) AS price FROM hw_accessories	";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result[0]); 
  });
});

app.get("/swtotalprice", (req, res) => {
  const sql = "SELECT sum(price) AS price FROM sw_asset";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result[0]); 
  });
});

app.get("/swyeartotalprice", (req, res) => {
  const sql = "SELECT sum(price) AS price FROM sw_yearly";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result[0]); 
  });
});


app.listen(process.env.PORT, () => {
  console.log("running");
});
