import express from "express";
import mysql from "mysql";
import cors from "cors";
import bodyParser from "body-parser";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
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
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

//Login
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
            var tokenPayload = {
              username: users[0].username,
            };
            var token = jwt.sign(tokenPayload, secret, {
              expiresIn: "2h",
            });
            res.json({ status: "ok", message: "Login success", token });
          } else {
            res.json({ status: "error", message: "Login failed" });
          }
        }
      );
    }
  );
});
//authen
/* app.post("/authen", jsonParser, function (req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    var decoded = jwt.verify(token, secret);
    res.json({ status: "ok", decoded });
  } catch (err) {
    res.json({ status: "error", message: err.message });
  }
}); */
//User
app.get("/user", (req, res) => {
  const sql = "SELECT *  FROM users";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//add
app.post("/adduser", jsonParser, function (req, res, next) {
  const minUsernameLength = 5;
  const maxUsernameLength = 20;
  const minPasswordLength = 8;
  const maxPasswordLength = 30;
  const minFullNameLength = 1;
  const maxFullNameLength = 50;
  const { username, password, fullname, role } = req.body;

  if (
    !username ||
    username.length < minUsernameLength ||
    username.length > maxUsernameLength
  ) {
    return res.json({
      status: "error",
      message: `Username must be between ${minUsernameLength} and ${maxUsernameLength} characters.`,
    });
  }
  if (
    !password ||
    password.length < minPasswordLength ||
    password.length > maxPasswordLength
  ) {
    return res.json({
      status: "error",
      message: `Password must be between ${minPasswordLength} and ${maxPasswordLength} characters.`,
    });
  }
  if (
    !fullname ||
    fullname.length < minFullNameLength ||
    fullname.length > maxFullNameLength
  ) {
    return res.json({
      status: "error",
      message: `Fullname must be between ${minFullNameLength} and ${maxFullNameLength} characters.`,
    });
  }
  const validRoles = ["Admin", "User"];
  if (!role || !validRoles.includes(role)) {
    return res.json({
      status: "error",
      message: `Invalid role. Valid roles are: ${validRoles.join(", ")}`,
    });
  }
  bcrypt.hash(password, saltRounds, function (err, hash) {
    if (err) {
      return res.json({ status: "error", message: err });
    }

    db.query(
      "INSERT INTO users (fullname, username, password, role) VALUES (?, ?, ?, ?)",
      [fullname, username, hash, role],
      function (err, results, fields) {
        if (err) {
          return res.json({ status: "error", message: err });
        }
        return res.json({ status: "ok" });
      }
    );
  });
});
//checkusername
app.post("/check-username", (req, res) => {
  const { username } = req.body;
  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    (err, results) => {
      if (err) {
        console.error(err);
        res.status(500).json({ error: "Database error", details: err.message });
      } else {
        const user = results[0];
        if (user) {
          res.json({ usernameExists: true, userId: user.id });
        } else {
          res.json({ usernameExists: false });
        }
      }
    }
  );
});
//reset password by username
app.put("/users/:id/reset-password", async (req, res) => {
  const id = req.params.id;
  const newPassword = req.body.newPassword;
  try {
    if (newPassword.length < 8 || newPassword.length > 30) {
      return res.status(400).json({
        status: "error",
        message: "Password must be between 8 and 30 characters long",
      });
    }
    const hash = await bcrypt.hash(newPassword, saltRounds);
    db.query(
      "UPDATE users SET `password`=? WHERE id=?",
      [hash, id],
      function (err, results, fields) {
        if (err) {
          console.error("Error updating password in the database:", err);
          return res.status(500).json({
            status: "error",
            message: "Error updating password in the database",
          });
        }
        return res.json({ status: "ok" });
      }
    );
  } catch (error) {
    console.error("Error hashing password:", error);
    return res
      .status(500)
      .json({ status: "error", message: "Error hashing password" });
  }
});
//get user by id
app.get("/datauser/:id", (req, res) => {
  const sql = "SELECT *  FROM users WHERE id = ?";
  const id = req.params.id
  db.query(sql, [id],(err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//update user data
app.put("/updateuser/:id", (req, res) => {
  const requiredFields = [
    `fullname`,
    `username`,
    `role`,
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
    "UPDATE users SET `fullname`=?, `username`=?, `role`=? WHERE id=?";
  const id = req.params.id;
  db.query(
    sql,
    [
      req.body.fullname,
      req.body.username,
      req.body.role,
      id,
    ],
    (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    }
  );
});

// CRUD API
//Hardware
//get
app.get("/hw-asset", (req, res) => {
  const sql =
    "SELECT *, GROUP_CONCAT(softwareinstall SEPARATOR ', ') as softwareinstall FROM hw_asset LEFT JOIN gtbinstall ON hw_asset.hwassetnumber = gtbinstall.assetinstall GROUP BY hw_asset.hwassetnumber";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//add
app.post("/addhw-asset", (req, res) => {
  const requiredFields = [
    "hwassetnumber",
    "brand",
    "model",
    "user",
    "location",
    "dev",
    "spec",
    "serialnumber",
    "price",
    "receivedate",
    "invoicenumber",
    "ponumber",
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
  const assetnum = req.body.hwassetnumber.replace(/\W/g, "").replace("-", "");
  const sqlCheckDuplicateAsset =
    "SELECT COUNT(*) AS count FROM hw_asset WHERE REPLACE(hwassetnumber, '-', '') = ?;";
  db.query(sqlCheckDuplicateAsset, assetnum, (err, result) => {
    if (err) return res.status(500).json(err);
    const count = result[0].count;
    if (count > 0) {
      return res.json({
        status: "error",
        message: "Asset Number already exists.",
      });
    } else {
      const sqlCheckDuplicateAmortized =
        "SELECT COUNT(*) AS count FROM hw_amortized WHERE REPLACE(hwassetnumber, '-', '') = ?;";
      db.query(sqlCheckDuplicateAmortized, assetnum, (err, result) => {
        if (err) return res.status(500).json(err);
        const countAmortized = result[0].count;
        if (countAmortized > 0) {
          return res.json({
            status: "erroramortized",
            message: "Asset Number already exists in amortized assets.",
          });
        } else {
          const software = req.body.softwareinstall;

          if (software && software.length > 0) {
            const sqlCheckDuplicateSoftware =
              "SELECT * FROM gtbinstall WHERE softwareinstall = ?";

            db.query(sqlCheckDuplicateSoftware, software, (err, result) => {
              if (err) return res.status(500).json(err);

              if (result.length > 0) {
                const assetInstallValue = result[0].assetinstall;

                return res.json({
                  status: "errorsoftware",
                  message: "Software already exists.",
                  assetInstall: assetInstallValue,
                });
              } else {
                const sql =
                  "INSERT INTO hw_asset (`hwassetnumber`, `brand`, `model`, `user`, `location`, `dev`, `spec`, `serialnumber`, `price`, `receivedate`, `invoicenumber`, `ponumber`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
                const values = [
                  req.body.hwassetnumber,
                  req.body.brand,
                  req.body.model,
                  req.body.user,
                  req.body.location,
                  req.body.dev,
                  req.body.spec,
                  req.body.serialnumber,
                  req.body.price,
                  req.body.receivedate,
                  req.body.invoicenumber,
                  req.body.ponumber,
                ];
                db.query(sql, values, (err, result) => {
                  if (err) return res.status(500).json(err);
                  const arr = req.body.softwareinstall;
                  const midtable =
                    "INSERT INTO gtbinstall (`assetinstall`, `softwareinstall`) VALUES (?, ?)";

                  for (let sw of arr) {
                    db.query(
                      midtable,
                      [req.body.hwassetnumber, sw],
                      (err, result) => {
                        if (err)
                          console.error("Error inserting software:", err);
                      }
                    );
                  }
                  return res
                    .status(201)
                    .json({ Message: "Asset added successfully." });
                });
              }
            });
          } else {
            const sql =
              "INSERT INTO hw_asset (`hwassetnumber`, `brand`, `model`, `user`, `location`, `dev`, `spec`, `serialnumber`, `price`, `receivedate`, `invoicenumber`, `ponumber`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
            const values = [
              req.body.hwassetnumber,
              req.body.brand,
              req.body.model,
              req.body.user,
              req.body.location,
              req.body.dev,
              req.body.spec,
              req.body.serialnumber,
              req.body.price,
              req.body.receivedate,
              req.body.invoicenumber,
              req.body.ponumber,
            ];
            db.query(sql, values, (err, result) => {
              if (err) return res.status(500).json(err);
              return res
                .status(201)
                .json({ Message: "Asset added successfully." });
            });
          }
        }
      });
    }
  });
});
//read
app.get("/readhw-asset/:id", (req, res) => {
  const sql =
    "SELECT *, GROUP_CONCAT(softwareinstall SEPARATOR ', ') as softwareinstall FROM hw_asset LEFT JOIN gtbinstall ON hw_asset.hwassetnumber = gtbinstall.assetinstall WHERE id = ? GROUP BY hw_asset.hwassetnumber";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//update
app.put("/updatehw-asset/:id", (req, res) => {
  const requiredFields = [
    "hwassetnumber",
    "brand",
    "model",
    "user",
    "location",
    "dev",
    "spec",
    "serialnumber",
    "price",
    "receivedate",
    "invoicenumber",
    "ponumber",
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
  const sqlCheckDuplicate =
    "SELECT COUNT(*) AS count FROM hw_asset WHERE hwassetnumber = ? AND id != ?";
  const sqlCheckDuplicateAmortized =
    "SELECT COUNT(*) AS count FROM hw_amortized WHERE hwassetnumber = ?";
  const assetnum = req.body.hwassetnumber;
  const id = req.params.id;
  db.query(sqlCheckDuplicate, [assetnum, id], (err, result) => {
    if (err) return res.status(500).json(err);
    const count = result[0].count;
    if (count > 0) {
      return res.json({
        status: "error",
        message: "Asset Number already exists.",
      });
    }
    db.query(sqlCheckDuplicateAmortized, assetnum, (err, result) => {
      if (err) return res.status(500).json(err);
      const countAmortized = result[0].count;
      if (countAmortized > 0) {
        return res.json({
          status: "erroramortized",
          message: "Asset Number already exists in amortized assets.",
        });
      }
      const sql =
        "UPDATE hw_asset SET `hwassetnumber`=?, `brand`=?, `model`=?, `user`=?, `location`=?, `dev`=?, `spec`=?, `serialnumber`=?, `price`=?, `receivedate`=?, `invoicenumber`=?, `ponumber`=? WHERE id=?";
      db.query(
        sql,
        [
          req.body.hwassetnumber,
          req.body.brand,
          req.body.model,
          req.body.user,
          req.body.location,
          req.body.dev,
          req.body.spec,
          req.body.serialnumber,
          req.body.price,
          req.body.receivedate,
          req.body.invoicenumber,
          req.body.ponumber,
          id,
        ],
        (err, result) => {
          if (err) return res.json({ Message: "Error inside server" });
          const delmid =
            "DELETE assetinstall FROM gtbinstall JOIN hw_asset ON hwassetnumber = assetinstall WHERE id = ?";
          db.query(delmid, [id], (err, result) => {
            if (err) return res.json({ Message: "Error inside server" });
            const arr = req.body.softwareinstall;
            const midtable =
              "INSERT INTO gtbinstall (`assetinstall`, `softwareinstall`) VALUES (?, ?)";
            for (let sw of arr) {
              db.query(
                midtable,
                [req.body.hwassetnumber, sw],
                (err, result) => {}
              );
            }
          });
          return res.json(result);
        }
      );
    });
  });
});
//delete
app.delete("/deletehw-asset/:id", (req, res) => {
  const sql = "DELETE FROM hw_asset WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

//Accessories
//get
app.get("/hw-accessories", (req, res) => {
  const sql = "SELECT * FROM accessories";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//add
app.post("/addhw-accessories", (req, res) => {
  const requiredFields = [
    `type`,
    `detail`,
    `serialnumber`,
    `assetinstall`,
    `location`,
    `dev`,
    `price`,
    `receivedate`,
    "invoicenumber",
    "ponumber",
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
    "INSERT INTO accessories (`type`, `detail`, `serialnumber`, `assetinstall`, `location`,  `dev`, `price`, `receivedate`, `invoicenumber`, `ponumber`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  const values = [
    req.body.type,
    req.body.detail,
    req.body.serialnumber,
    req.body.assetinstall,
    req.body.location,
    req.body.dev,
    req.body.price,
    req.body.receivedate,
    req.body.invoicenumber,
    req.body.ponumber,
  ];
  db.query(sql, values, (err, result) => {
    if (err) return res.json(err);
    return res.json(result);
  });
});
//read
app.get("/readhw-accessories/:id", (req, res) => {
  const sql = "SELECT * FROM accessories WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//update
app.put("/updatehw-accessories/:id", (req, res) => {
  const requiredFields = [
    `type`,
    `detail`,
    `serialnumber`,
    `assetinstall`,
    `location`,
    `dev`,
    `price`,
    `receivedate`,
    `invoicenumber`,
    `ponumber`,
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
    "UPDATE accessories SET `type`=?, `detail`=?, `serialnumber`=?, `assetinstall`=?, `location`=?, `dev`=?, `price`=?, `receivedate`=?, `invoicenumber`=?, `ponumber`=? WHERE id=?";
  const id = req.params.id;
  db.query(
    sql,
    [
      req.body.type,
      req.body.detail,
      req.body.serialnumber,
      req.body.assetinstall,
      req.body.location,
      req.body.dev,
      req.body.price,
      req.body.receivedate,
      req.body.invoicenumber,
      req.body.ponumber,
      id,
    ],
    (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    }
  );
});
//delete
app.delete("/deletehw-accessories/:id", (req, res) => {
  const sql = "DELETE FROM accessories WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//gethwassetnumber
app.get("/accessories-asset", (req, res) => {
  const sql = "SELECT hwassetnumber FROM hw_asset";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

//Software
//get
app.get("/sw-asset", (req, res) => {
  const sql =
    "SELECT * FROM sw_asset LEFT JOIN gtbinstall ON swassetnumber = softwareinstall";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//add
app.post("/addsw-asset", (req, res) => {
  const requiredFields = [
    `swassetnumber`,
    `name`,
    `serialnumber`,
    `softwarekey`,
    `user`,
    `location`,
    `dev`,
    `price`,
    `receivedate`,
    `invoicenumber`,
    `ponumber`,
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
  const assetnum = req.body.swassetnumber.replace(/\W/g, "");
  const sqlCheckDuplicate =
    "SELECT COUNT(*) AS count FROM sw_asset WHERE REPLACE(swassetnumber, '-', '') = ?";
  db.query(sqlCheckDuplicate, assetnum, (err, result) => {
    if (err) return res.status(500).json(err);
    const count = result[0].count;
    if (count > 0) {
      return res.json({
        status: "errorsoftware",
        message: "Asset Number already exists.",
      });
    } else {
      const sql =
        "INSERT INTO sw_asset (`swassetnumber`, `name`, `serialnumber`, `softwarekey`, `user`, `location`, `dev`, `price`, `receivedate`, `invoicenumber`, `ponumber`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
      const values = [
        req.body.swassetnumber,
        req.body.name,
        req.body.serialnumber,
        req.body.softwarekey,
        req.body.user,
        req.body.location,
        req.body.dev,
        req.body.price,
        req.body.receivedate,
        req.body.invoicenumber,
        req.body.ponumber,
      ];
      db.query(sql, values, (err, result) => {
        if (err) return res.json(err);
        return res.json(result);
      });
    }
  });
});
//read
app.get("/readsw-asset/:id", (req, res) => {
  const sql =
    "SELECT * FROM sw_asset LEFT JOIN gtbinstall ON swassetnumber = softwareinstall WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//update
app.put("/updatesw-asset/:id", (req, res) => {
  const requiredFields = [
    `swassetnumber`,
    `name`,
    `serialnumber`,
    `softwarekey`,
    `user`,
    `location`,
    `price`,
    `receivedate`,
    `invoicenumber`,
    `ponumber`,
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
  const sqlCheckDuplicate =
    "SELECT COUNT(*) AS count FROM sw_asset WHERE REPLACE(swassetnumber, '-', '') = ? AND id != ?";
  const assetnum = req.body.swassetnumber.replace(/\W/g, "");
  const id = req.params.id;
  db.query(sqlCheckDuplicate, [assetnum, id], (err, result) => {
    if (err) return res.status(500).json({ Message: "Error inside server" });
    const count = result[0].count;
    if (count > 0) {
      return res.json({
        status: "error",
        message: "Asset Number already exists.",
      });
    } else {
      const sql =
        "UPDATE sw_asset SET `swassetnumber`=?, `name`=?, `serialnumber`=?, `softwarekey`=?, `user`=?, `location`=?, `price`=?, `receivedate`=?, `invoicenumber`=?, `ponumber`=? WHERE id=?";
      db.query(
        sql,
        [
          req.body.swassetnumber,
          req.body.name,
          req.body.serialnumber,
          req.body.softwarekey,
          req.body.user,
          req.body.location,
          req.body.price,
          req.body.receivedate,
          req.body.invoicenumber,
          req.body.ponumber,
          id,
        ],
        (err, result) => {
          if (err)
            return res.status(500).json({ Message: "Error inside server" });

          return res.json({ Message: "Update successful.", result });
        }
      );
    }
  });
});
//delete
app.delete("/deletesw-asset/:id", (req, res) => {
  const sql = "DELETE FROM sw_asset WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//get number+name
app.get("/sw", (req, res) => {
  const sql = "SELECT `swassetnumber`, `name` FROM `sw_asset`";
  db.query(sql, (err, result) => {
    if (err) {
      console.error("Error executing query:", err);
      return res.json({ Message: "Error executing query" });
    }
    console.log("Result:", result);
    const assets = result.map((row) => ({
      swassetnumber: row.swassetnumber,
      name: row.name,
    }));
    return res.json(assets);
  });
});

//Software Yeayly
//get
app.get("/sw-yearly", (req, res) => {
  const sql = "SELECT * FROM sw_yearly";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//add
app.post("/addsw-yearly", (req, res) => {
  const requiredFields = [
    "name",
    "serialnumber",
    "assetinstall",
    "receivedate",
    "expiredate",
    "price",
    "invoicenumber",
    "ponumber",
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
  if (new Date(req.body.receivedate) > new Date(req.body.expiredate)) {
    return res.json({
      status: "errordate",
      Message: "receivedate cannot be after expiredate.",
    });
  }
  const sql =
    "INSERT INTO sw_yearly (`name`, `serialnumber`,`assetinstall`, `receivedate`, `expiredate`, `price`, `invoicenumber`, `ponumber`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
  const values = [
    req.body.name,
    req.body.serialnumber,
    req.body.assetinstall,
    req.body.receivedate,
    req.body.expiredate,
    req.body.price,
    req.body.invoicenumber,
    req.body.ponumber,
  ];
  db.query(sql, values, (err, result) => {
    if (err) return res.json(err);
    return res.json(result);
  });
});
//read
app.get("/readsw-yearly/:id", (req, res) => {
  const sql = "SELECT * FROM sw_yearly WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//update
app.put("/updatesw-yearly/:id", (req, res) => {
  const requiredFields = [
    `name`,
    `serialnumber`,
    `assetinstall`,
    `receivedate`,
    `expiredate`,
    `price`,
    `invoicenumber`,
    `ponumber`,
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
  if (new Date(req.body.receivedate) > new Date(req.body.expiredate)) {
    return res.json({
      status: "errordate",
      Message: "receivedate cannot be after expiredate.",
    });
  }
  const sql =
    "UPDATE sw_yearly SET `name`=?, `serialnumber`=?,`assetinstall`=?, `receivedate`=?, `expiredate`=?, `price`=?, `invoicenumber`=?, `ponumber`=? WHERE id=?";
  const id = req.params.id;
  db.query(
    sql,
    [
      req.body.name,
      req.body.serialnumber,
      req.body.assetinstall,
      req.body.receivedate,
      req.body.expiredate,
      req.body.price,
      req.body.invoicenumber,
      req.body.ponumber,
      id,
    ],
    (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    }
  );
});
//delete
app.delete("/deletesw-yearly/:id", (req, res) => {
  const sql = "DELETE FROM sw_yearly WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

//Amortized
//get
app.get("/hw-amortized", (req, res) => {
  const sql = "SELECT * FROM hw_amortized";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//add
app.post("/addhw-amortized", (req, res) => {
  const requiredFields = [
    "hwassetnumber",
    "brand",
    "model",
    "user",
    "location",
    "dev",
    "spec",
    "serialnumber",
    "price",
    "receivedate",
    "invoicenumber",
    "ponumber",
    "amortizeddate",
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
  const sqlCheckDuplicateAmortized =
    "SELECT COUNT(*) AS count FROM hw_amortized WHERE hwassetnumber = ?";
  const assetnum = req.body.hwassetnumber;
  db.query(sqlCheckDuplicateAmortized, assetnum, (err, result) => {
    if (err) return res.status(500).json(err);
    const count = result[0].count;
    if (count > 0) {
      return res.json({
        status: "error",
        message: "Asset Number already exists.",
      });
    } else {
      const sqlCheckDuplicateAsset =
        "SELECT COUNT(*) AS count FROM hw_asset WHERE hwassetnumber = ?";
      db.query(sqlCheckDuplicateAsset, assetnum, (err, result) => {
        if (err) return res.status(500).json(err);
        const countAsset = result[0].count;
        if (countAsset > 0) {
          return res.json({
            status: "errorhardware",
            message: "Asset Number already exists in Hardware assets.",
          });
        } else {
          const sql =
            "INSERT INTO hw_amortized (`hwassetnumber`, `brand`, `model`, `user`, `location`, `dev`, `spec`, `serialnumber`, `price`, `receivedate`, `invoicenumber`, `ponumber`, `amortizeddate`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
          const values = [
            req.body.hwassetnumber,
            req.body.brand,
            req.body.model,
            req.body.user,
            req.body.location,
            req.body.dev,
            req.body.spec,
            req.body.serialnumber,
            req.body.price,
            req.body.receivedate,
            req.body.invoicenumber,
            req.body.ponumber,
            req.body.amortizeddate,
          ];
          db.query(sql, values, (err, result) => {
            if (err) {
              console.error("Error inserting data:", err);
              return res.status(500).json({ message: "Internal Server Error" });
            }
            return res.json(result);
          });
        }
      });
    }
  });
});
//read
app.get("/readhw-amortized/:id", (req, res) => {
  const sql = "SELECT * FROM hw_amortized WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//update
app.put("/updatehw-amortized/:id", (req, res) => {
  const requiredFields = [
    "hwassetnumber",
    "brand",
    "model",
    "user",
    "location",
    "dev",
    "spec",
    "serialnumber",
    "price",
    "receivedate",
    "invoicenumber",
    "ponumber",
    "amortizeddate",
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
  const sqlCheckDuplicate =
    "SELECT COUNT(*) AS count FROM hw_amortized WHERE assetnum = ?";
  const assetnum = req.body.hwassetnumber;
  db.query(sqlCheckDuplicate, assetnum, (err, result) => {
    if (err) return res.status(500).json(err);
    const count = result[0].count;
    if (count > 0) {
      return res.json({
        status: "error",
        message: "Asset Number already exists.",
      });
    } else {
      const sql =
        "UPDATE hw_amortized SET `hwassetnumber`=?, `brand`=?, `model`=?, `user`=?, `location`=?, `dev`=?, `spec`=?, `serialnumber`=?, `price`=?, `receivedate`=?, `invoicenumber`=?, `ponumber`=?, `amortizeddate`=? WHERE id=?";
      const id = req.params.id;
      db.query(
        sql,
        [
          req.body.ahwassetnumber,
          req.body.brand,
          req.body.model,
          req.body.user,
          req.body.location,
          req.body.dev,
          req.body.spec,
          req.body.serialnumber,
          req.body.software,
          req.body.price,
          req.body.receivedate,
          req.body.invoicenumber,
          req.body.ponumber,
          req.body.amortizeddate,
          id,
        ],
        (err, result) => {
          if (err) return res.json({ Message: "Error inside server" });
          return res.json(result);
        }
      );
    }
  });
});
//delete
app.delete("/deletehw-amortized/:id", (req, res) => {
  const sql = "DELETE FROM hw_amortized WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
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
  const sql = "SELECT COUNT(id) AS hw_accessories	 FROM accessories";
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
  const sql = "SELECT sum(price) AS price FROM accessories";
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
  const currentDate = new Date().toISOString().split("T")[0];
  const sql = `SELECT SUM(price) AS price FROM sw_yearly WHERE expiredate >= '${currentDate}'`;
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result[0]);
  });
});

//Move
app.post("/movetohw-amortized/:id", (req, res) => {
  const checkSql =
    "SELECT COUNT(*) AS count FROM hw_amortized WHERE hwassetnumber = (SELECT hwassetnumber FROM hw_asset WHERE id = ?)";
  const sql =
    "INSERT INTO hw_amortized (`hwassetnumber`, `brand`, `model`, `user`, `location`, `dev`, `spec`, `serialnumber`, `price`, `receivedate`, `invoicenumber`, `ponumber`, `amortizeddate`) SELECT hwassetnumber, brand, model, user, location, dev, spec, serialnumber, price, receivedate, invoicenumber, ponumber, DATE(CURRENT_TIMESTAMP()) FROM hw_asset WHERE id = ?";
  const sqldel = "DELETE FROM hw_asset WHERE id = ?";
  const id = req.params.id;
  db.query(checkSql, [id], (err, checkResult) => {
    if (err) return res.status(500).json(err);
    const count = checkResult[0].count;
    if (count > 0) {
      return res.json({
        status: "error",
        message: "Asset Number already exists.",
      });
    } else {
      db.query(sql, [id], (err, result) => {
        if (err) return res.json(err);
        db.query(sqldel, [id], (err, deleteResult) => {
          if (err) return res.json(err);
          return res.json(result);
        });
      });
    }
  });
});

app.post("/moveback-hwasset/:id", (req, res) => {
  const checkSql =
    "SELECT COUNT(*) AS count FROM hw_asset WHERE assetnum = (SELECT assetnum FROM hw_amortized WHERE id = ?)";
  const sql =
    "INSERT INTO hw_asset (`assetnum`, `brand`, `model`, `user`, `location`, `dev`,`spec`, `serialnumber`, `software`, `price`, `receivedate`, `invoicenum`, `ponum`) SELECT assetnum, brand, model, user, location, dev, spec, serialnumber, software, price, receivedate, invoicenum, ponum FROM hw_amortized WHERE id = ?";
  const sqldel = "DELETE FROM hw_amortized WHERE id = ?";
  const id = req.params.id;

  db.query(checkSql, [id], (err, checkResult) => {
    if (err) return res.status(500).json(err);
    const count = checkResult[0].count;
    if (count > 0) {
      return res.json({
        status: "error",
        message: "Asset Number already exists.",
      });
    } else {
      db.query(sql, [id], (err, insertResult) => {
        if (err) return res.json(err);
        db.query(sqldel, [id], (err, deleteResult) => {
          if (err) return res.json(err);
          return res.json(insertResult);
        });
      });
    }
  });
});

app.delete("/deletemid/:id", (req, res) => {
  const sql =
    "DELETE assetinstall FROM gtbinstall JOIN hw_asset ON hwassetnumber = assetinstall WHERE id = hw_asset.id";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

//midtable
app.get("/hw-softwareinstall/:id", (req, res) => {
  const id = req.params.id;
  const sql =
    "SELECT GROUP_CONCAT(softwareinstall SEPARATOR ', ') as softwareinstall FROM hw_asset JOIN gtbinstall ON hwassetnumber = assetinstall WHERE id = ? GROUP BY hwassetnumber";
  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    const softwareinstallData = result[0].softwareinstall;
    return res.send(softwareinstallData);
  });
});
//get assetnuber
app.get("/hw-assetnumber", (req, res) => {
  const sql = "SELECT hwassetnumber FROM hw_asset";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.get("/sw-assetnumber", (req, res) => {
  const sql = "SELECT swassetnumber FROM sw_asset";
  db.query(sql, (err, result) => {
    if (err) {
      console.error("Database query error:", err);
      return res.status(500).json({ Message: "Error inside server" });
    }
    if (Array.isArray(result) && result.length > 0) {
      const cleanResult = result.map((item) => {
        if (item.swassetnumber && typeof item.swassetnumber === "string") {
          return item.swassetnumber.replace(/[-,]/g, "");
        } else {
          return null;
        }
      });
      return res.json(cleanResult);
    } else {
      return res.json([]); // Return empty array if no data found
    }
  });
});

app.listen(process.env.PORT, () => {
  console.log("Server is running");
});
