import express from "express";
import mysql from "mysql";
import cors from "cors";
import bodyParser from "body-parser";
import crypto from "crypto";
import jwt from "jsonwebtoken";
import dotenv from "dotenv";
dotenv.config();

const jsonParser = bodyParser.json();
const secret = process.env.SECRET_KEY;
const app = express();
app.use(cors());
app.use(express.json());
const itsecret = process.env.IT_SECRET;

const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_DATABASE,
});

// Login
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

      const hashedPassword = hashPassword(req.body.password);

      if (hashedPassword === users[0].password) {
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
});
// AddUser
app.post("/adduser", jsonParser, function (req, res, next) {
  const minUsernameLength = 5;
  const maxUsernameLength = 20;
  const minPasswordLength = 8;
  const maxPasswordLength = 30;
  const minFullNameLength = 1;
  const maxFullNameLength = 50;
  const { username, password, fullname, role } = req.body;
  db.query(
    "SELECT * FROM users WHERE username = ?",
    [username],
    function (err, existingUsers, fields) {
      if (err) {
        return res.json({ status: "error", message: err });
      }
      if (existingUsers.length > 0) {
        return res.json({
          status: "error",
          message: "Username already exists",
        });
      }
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

      const hashedPassword = hashPassword(password);
      const hashSecret = hashPassword(itsecret);

      db.query(
        "INSERT INTO users (fullname, username, password, role, itsecret) VALUES (?, ?, ?, ?, ?)",
        [fullname, username, hashedPassword, role, hashSecret],
        function (err, results, fields) {
          if (err) {
            return res.json({ status: "error", message: err });
          }
          return res.json({ status: "ok" });
        }
      );
    }
  );
});
// Hashing function
function hashPassword(password) {
  const hash = crypto.createHash("sha256");
  hash.update(password);
  return hash.digest("hex");
}
//User
app.get("/user", (req, res) => {
  const sql = "SELECT *  FROM users";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//checkusername
app.post("/check-username", (req, res) => {
  const { username, itsecret } = req.body;
  const hashSecret = hashPassword(itsecret);
  db.query(
    "SELECT * FROM users WHERE username = ? AND itsecret = ?",
    [username, hashSecret],
    (err, results) => {
      if (err) {
        console.error(err);
        res.json({ statusbar: "Database error", details: err.message });
      } else {
        if (results.length === 0) {
          res.json({ status: "ITSecret", message: "Invalid IT Secret" });
        } else {
          const user = results[0];
          res.json({ usernameExists: true, userId: user.id });
        }
      }
    }
  );
});
//reset password by username
app.put("/users/:id/reset-password", (req, res) => {
  const id = req.params.id;
  const newPassword = req.body.newPassword;
  try {
    if (newPassword.length < 8 || newPassword.length > 30) {
      return res.status(400).json({
        status: "error",
        message: "Password must be between 8 and 30 characters long",
      });
    }
    const hashedPassword = hashPassword(newPassword);
    db.query(
      "UPDATE users SET `password`=? WHERE id=?",
      [hashedPassword, id],
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
  const id = req.params.id;
  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//update user data
app.put("/updateuser/:id", (req, res) => {
  const requiredFields = [`fullname`, `username`, `role`];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  const id = req.params.id;
  const newUsername = req.body.username;

  db.query(
    "SELECT * FROM users WHERE username = ? AND id != ?",
    [newUsername, id],
    (usernameErr, existingUsers) => {
      if (usernameErr) {
        return res.json({ Message: "Error checking username." });
      }
      if (existingUsers.length > 0) {
        return res.status(400).json({ Message: "Username already exists." });
      }
      const sql =
        "UPDATE users SET `fullname`=?, `username`=?, `role`=? WHERE id=?";
      db.query(
        sql,
        [req.body.fullname, newUsername, req.body.role, id],
        (updateErr, result) => {
          if (updateErr) {
            return res.json({ Message: "Error inside server" });
          }
          return res.json(result);
        }
      );
    }
  );
});
//authen
app.post("/authen", jsonParser, function (req, res, next) {
  try {
    const token = req.headers.authorization.split(" ")[1];
    var decoded = jwt.verify(token, secret);
    res.json({ status: "ok", decoded });
  } catch (err) {
    res.json({ status: "error", message: err.message });
  }
});

//Main CRUD API
//Get
app.get("/get-hardware", (req, res) => {
  const sql =
    "SELECT hardware.*, GROUP_CONCAT(pc_install_sw.swinstall SEPARATOR ', ') as softwareinstall FROM hardware LEFT JOIN pc_install_sw ON hardware.hw_assetnumber =  pc_install_sw.pcinstall WHERE NOT hardware.hw_amortized GROUP BY hardware.hw_assetnumber";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    const data = result.map((item) => {
      if (item.softwareinstall === null) {
        return { ...item, softwareinstall: "None Install" };
      } else {
        return item;
      }
    });
    return res.json(data);
  });
});
app.get("/get-accessories", (req, res) => {
  const sql = "SELECT * FROM accessories";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.get("/get-software", (req, res) => {
  const sql =
    "SELECT software.*,pc_install_sw.*,hardware.hw_assetnumber,hardware.hw_amortized FROM software LEFT JOIN pc_install_sw ON sw_assetnumber = swinstall LEFT JOIN hardware ON pcinstall = hw_assetnumber";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });

    const data = result.map((item) => {
      if (item.sw_assetnumber === item.swinstall) {
        if (item.hw_amortized === 0) {
          return { ...item, pcinstall: item.hw_assetnumber };
        } else {
          return { ...item, pcinstall: "Amortized" };
        }
      } else {
        return { ...item, pcinstall: "Not install" };
      }
    });

    return res.json(data);
  });
});
app.get("/get-yearlysoftware", (req, res) => {
  const sql = "SELECT * FROM yearlysoftware";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.get("/get-amortized", (req, res) => {
  const sql =
    "SELECT *, IFNULL(GROUP_CONCAT(swinstall SEPARATOR ', '), 'None install') as softwareinstall FROM hardware LEFT JOIN pc_install_sw ON hardware.hw_assetnumber = pc_install_sw.pcinstall WHERE hardware.hw_amortized GROUP BY hardware.hw_assetnumber";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//Add
app.post("/add-hardware", (req, res) => {
  const requiredFields = [
    "hw_assetnumber",
    "hw_brand",
    "hw_model",
    "hw_user",
    "hw_location",
    "hw_department",
    "hw_spec",
    "hw_serialnumber",
    "hw_price",
    "hw_receivedate",
    "hw_invoicenumber",
    "hw_ponumber",
  ];

  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  const assetnum = req.body.hw_assetnumber.replace(/\W/g, "").replace("-", "");
  const sqlCheckDuplicateAsset =
    "SELECT COUNT(*) AS count FROM hardware WHERE REPLACE(hw_assetnumber, '-', '') = ?;";
  db.query(sqlCheckDuplicateAsset, assetnum, (err, result) => {
    if (err) {
      return res.status(500).json(err);
    }
    const count = result[0].count;
    if (count > 0) {
      return res.json({
        status: "error",
        message: "Asset Number already exists.",
      });
    } else {
      const sql =
        "INSERT INTO hardware (`hw_assetnumber`, `hw_brand`, `hw_model`, `hw_user`, `hw_location`, `hw_department`, `hw_spec`, `hw_serialnumber`, `hw_price`, `hw_receivedate`, `hw_invoicenumber`, `hw_ponumber`, `hw_amortizeddate`, `hw_amortized`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
      const values = [
        req.body.hw_assetnumber,
        req.body.hw_brand,
        req.body.hw_model,
        req.body.hw_user,
        req.body.hw_location,
        req.body.hw_department,
        req.body.hw_spec,
        req.body.hw_serialnumber,
        req.body.hw_price,
        req.body.hw_receivedate,
        req.body.hw_invoicenumber,
        req.body.hw_ponumber,
        null,
        false,
      ];
      db.query(sql, values, (err, result) => {
        if (err) {
          return res.status(500).json(err);
        }
        const software = req.body.hw_softwareinstall;
        if (software.length === 0 || software == "None Install") {
          return res.status(201).json({ Message: "Asset added successfully." });
        } else {
          const sqlCheckDuplicateSoftware =
            "SELECT * FROM pc_install_sw WHERE swinstall IN (?)";
          db.query(sqlCheckDuplicateSoftware, [software], (err, result) => {
            if (err) return res.status(500).json(err);
            if (result.length > 0) {
              const assetInstallValue = result[0].assetinstall;
              return res.json({
                status: "errorsoftware",
                message: "Software already exists.",
                assetInstall: assetInstallValue,
              });
            } else {
              const midtable =
                "INSERT INTO pc_install_sw (`pcinstall`, `swinstall`) VALUES (?, ?)";
              for (let sw of software) {
                db.query(
                  midtable,
                  [req.body.hw_assetnumber, sw],
                  (err, result) => {
                    if (err) console.error("Error inserting software:", err);
                  }
                );
              }
              return res
                .status(201)
                .json({ Message: "Asset added successfully." });
            }
          });
        }
      });
    }
  });
});
app.post("/add-accessories", (req, res) => {
  const requiredFields = [
    `acc_type`,
    `acc_detail`,
    `acc_serialnumber`,
    `acc_assetinstall`,
    `acc_location`,
    `acc_department`,
    `acc_price`,
    `acc_receivedate`,
    `acc_invoicenumber`,
    `acc_ponumber`,
  ];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  const sql =
    "INSERT INTO accessories (`acc_type`, `acc_detail`, `acc_serialnumber`, `acc_assetinstall`, `acc_location`,  `acc_department`, `acc_price`, `acc_receivedate`, `acc_invoicenumber`, `acc_ponumber`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
  const values = [
    req.body.acc_type,
    req.body.acc_detail,
    req.body.acc_serialnumber,
    req.body.acc_assetinstall,
    req.body.acc_location,
    req.body.acc_department,
    req.body.acc_price,
    req.body.acc_receivedate,
    req.body.acc_invoicenumber,
    req.body.acc_ponumber,
  ];
  db.query(sql, values, (err, result) => {
    if (err) return res.json(err);
    return res.json(result);
  });
});
app.post("/add-software", (req, res) => {
  const requiredFields = [
    `sw_assetnumber`,
    `sw_name`,
    `sw_serialnumber`,
    `sw_softwarekey`,
    `sw_user`,
    `sw_location`,
    `sw_department`,
    `sw_price`,
    `sw_receivedate`,
    `sw_invoicenumber`,
    `sw_ponumber`,
  ];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  const assetnum = req.body.sw_assetnumber.replace(/\W/g, "");
  const sqlCheckDuplicate =
    "SELECT COUNT(*) AS count FROM software WHERE REPLACE(sw_assetnumber, '-', '') = ?";
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
        "INSERT INTO software (`sw_assetnumber`, `sw_name`, `sw_serialnumber`, `sw_softwarekey`, `sw_user`, `sw_location`, `sw_department`, `sw_price`, `sw_receivedate`, `sw_invoicenumber`, `sw_ponumber`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
      const values = [
        req.body.sw_assetnumber,
        req.body.sw_name,
        req.body.sw_serialnumber,
        req.body.sw_softwarekey,
        req.body.sw_user,
        req.body.sw_location,
        req.body.sw_department,
        req.body.sw_price,
        req.body.sw_receivedate,
        req.body.sw_invoicenumber,
        req.body.sw_ponumber,
      ];
      db.query(sql, values, (err, result) => {
        if (err) return res.json(err);
        return res.json(result);
      });
    }
  });
});
app.post("/add-yearlysoftware", (req, res) => {
  const requiredFields = [
    `ys_name`,
    `ys_serialnumber`,
    `ys_assetinstall`,
    `ys_receivedate`,
    `ys_expiredate`,
    `ys_price`,
    `ys_invoicenumber`,
    `ys_ponumber`,
  ];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  if (new Date(req.body.ys_receivedate) > new Date(req.body.ys_expiredate)) {
    return res.json({
      status: "errordate",
      Message: "receivedate cannot be after expiredate.",
    });
  }
  const sql =
    "INSERT INTO yearlysoftware (`ys_name`, `ys_serialnumber`, `ys_assetinstall`, `ys_receivedate`, `ys_expiredate`, `ys_price`, `ys_invoicenumber`, `ys_ponumber`) VALUES (?, ?, ?, ?, ?, ?, ?, ?)";
  const values = [
    req.body.ys_name,
    req.body.ys_serialnumber,
    req.body.ys_assetinstall,
    req.body.ys_receivedate,
    req.body.ys_expiredate,
    req.body.ys_price,
    req.body.ys_invoicenumber,
    req.body.ys_ponumber,
  ];
  db.query(sql, values, (err, result) => {
    if (err) return res.json(err);
    return res.json(result);
  });
});
app.post("/add-amortized", (req, res) => {
  const requiredFields = [
    `hw_assetnumber`,
    `hw_brand`,
    `hw_model`,
    `hw_user`,
    `hw_location`,
    `hw_department`,
    `hw_spec`,
    `hw_serialnumber`,
    `hw_price`,
    `hw_receivedate`,
    `hw_invoicenumber`,
    `hw_ponumber`,
    `hw_amortizeddate`,
  ];

  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  const assetnum = req.body.hw_assetnumber.replace(/\W/g, "").replace("-", "");
  const sqlCheckDuplicateAsset =
    "SELECT COUNT(*) AS count FROM hardware WHERE REPLACE(hw_assetnumber, '-', '') = ?;";
  db.query(sqlCheckDuplicateAsset, assetnum, (err, result) => {
    if (err) {
      return res.status(500).json(err);
    }
    const count = result[0].count;
    if (count > 0) {
      return res.json({
        status: "error",
        message: "Asset Number already exists.",
      });
    } else {
      const sql =
        "INSERT INTO hardware (`hw_assetnumber`, `hw_brand`, `hw_model`, `hw_user`, `hw_location`, `hw_department`, `hw_spec`, `hw_serialnumber`, `hw_price`, `hw_receivedate`, `hw_invoicenumber`, `hw_ponumber`, `hw_amortizeddate`, `hw_amortized`) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)";
      const values = [
        req.body.hw_assetnumber,
        req.body.hw_brand,
        req.body.hw_model,
        req.body.hw_user,
        req.body.hw_location,
        req.body.hw_department,
        req.body.hw_spec,
        req.body.hw_serialnumber,
        req.body.hw_price,
        req.body.hw_receivedate,
        req.body.hw_invoicenumber,
        req.body.hw_ponumber,
        req.body.hw_amortizeddate,
        true,
      ];
      db.query(sql, values, (err, result) => {
        if (err) {
          return res.status(500).json(err);
        }
        const software = req.body.hw_softwareinstall;
        if (software.length === 0 || software == "None Install") {
          return res.status(201).json({ Message: "Asset added successfully." });
        } else {
          const sqlCheckDuplicateSoftware =
            "SELECT * FROM pc_install_sw WHERE swinstall IN (?)";
          db.query(sqlCheckDuplicateSoftware, [software], (err, result) => {
            if (err) return res.status(500).json(err);
            if (result.length > 0) {
              const assetInstallValue = result[0].assetinstall;
              return res.json({
                status: "errorsoftware",
                message: "Software already exists.",
                assetInstall: assetInstallValue,
              });
            } else {
              const midtable =
                "INSERT INTO pc_install_sw (`pcinstall`, `swinstall`) VALUES (?, ?)";
              for (let sw of software) {
                db.query(
                  midtable,
                  [req.body.hw_assetnumber, sw],
                  (err, result) => {
                    if (err) console.error("Error inserting software:", err);
                  }
                );
              }
              return res
                .status(201)
                .json({ Message: "Asset added successfully." });
            }
          });
        }
      });
    }
  });
});
//Read
app.get("/read-hardware/:id", (req, res) => {
  const sql =
    "SELECT *, IFNULL(GROUP_CONCAT(swinstall SEPARATOR ', '), 'None Install') as softwareinstall FROM hardware LEFT JOIN pc_install_sw ON hardware.hw_assetnumber =pc_install_sw.pcinstall WHERE id = ? GROUP BY hardware.hw_assetnumber";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.get("/read-accessories/:id", (req, res) => {
  const sql = "SELECT * FROM accessories WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.get("/read-software/:id", (req, res) => {
  const sql =
    "SELECT software.*,pc_install_sw.*,hardware.hw_assetnumber,hardware.hw_amortized FROM software LEFT JOIN pc_install_sw ON sw_assetnumber = swinstall LEFT JOIN hardware ON pcinstall = hw_assetnumber WHERE software.id = ?";
  const id = req.params.id;

  db.query(sql, [id],(err, result) => {
    if (err) return res.json({ Message: "Error inside server" });

    const data = result.map((item) => {
      if (item.sw_assetnumber === item.swinstall) {
        if (item.hw_amortized === 0) {
          return { ...item, pcinstall: item.hw_assetnumber };
        } else {
          return { ...item, pcinstall: "Amortized" };
        }
      } else {
        return { ...item, pcinstall: "Not install" };
      }
    });

    return res.json(data);
  });
});
app.get("/read-yearlysoftware/:id", (req, res) => {
  const sql = "SELECT * FROM yearlysoftware WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.get("/read-amortized/:id", (req, res) => {
  const sql =
    "SELECT *, IFNULL(GROUP_CONCAT(swinstall SEPARATOR ', '), 'None Install') as softwareinstall FROM hardware LEFT JOIN pc_install_sw ON hardware.hw_assetnumber =pc_install_sw.pcinstall WHERE id = ? GROUP BY hardware.hw_assetnumber";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//Update
app.put("/update-hardware/:id", (req, res) => {
  const id = req.params.id;
  const requiredFields = [
    `hw_assetnumber`,
    `hw_brand`,
    `hw_model`,
    `hw_user`,
    `hw_location`,
    `hw_department`,
    `hw_spec`,
    `hw_serialnumber`,
    `hw_price`,
    `hw_receivedate`,
    `hw_invoicenumber`,
    `hw_ponumber`,
  ];
  for (const field of requiredFields) {
    if (!req.body[field]) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  const assetnum = req.body.hw_assetnumber.replace(/\W/g, "");
  const sqlCheckDuplicateAsset =
    "SELECT COUNT(*) AS count FROM hardware WHERE REPLACE(hw_assetnumber, '-', '') = ? AND id != ?";
  db.query(sqlCheckDuplicateAsset, [assetnum, id], (err, result) => {
    if (err) {
      console.error("Error checking duplicate asset:", err);
      return res.status(500).json({ Message: "Error inside server" });
    }
    const count = result[0].count;
    if (count > 0) {
      return res.json({
        status: "error",
        message: "Asset Number already exists.",
      });
    } else {
      const updateSql =
        "UPDATE hardware SET `hw_assetnumber`=?, `hw_brand`=?, `hw_model`=?, `hw_user`=?, `hw_location`=?, `hw_department`=?, `hw_spec`=?, `hw_serialnumber`=?, `hw_price`=?, `hw_receivedate`=?, `hw_invoicenumber`=?, `hw_ponumber`=? WHERE id=?";
      const values = [
        req.body.hw_assetnumber,
        req.body.hw_brand,
        req.body.hw_model,
        req.body.hw_user,
        req.body.hw_location,
        req.body.hw_department,
        req.body.hw_spec,
        req.body.hw_serialnumber,
        req.body.hw_price,
        req.body.hw_receivedate,
        req.body.hw_invoicenumber,
        req.body.hw_ponumber,
        id,
      ];
      db.query(updateSql, values, (err, result) => {
        if (err) {
          console.error("Error updating hardware asset:", err);
          return res.status(500).json({ Message: "Error inside server" });
        }
        const software = req.body.hw_softwareinstall;
        if (software == "None Install") {
          const del = "DELETE FROM pc_install_sw WHERE pcinstall = ? ";
          db.query(del, [req.body.hw_assetnumber], (err, result) => {
            if (err) {
              console.error(
                "Error deleting existing software installations:",
                err
              );
              return res.status(500).json({ Message: "Error inside server" });
            }
            res.json({
              status: "success",
              message: "Asset updated successfully.",
            });
          });
        } else {
          const sqlCheckDuplicateSoftware =
            "SELECT * FROM pc_install_sw WHERE swinstall IN (?) AND pcinstall != ?";
          db.query(
            sqlCheckDuplicateSoftware,
            [software, req.body.hw_assetnumber],
            (err, result) => {
              if (err) {
                console.error("Error checking duplicate software:", err);
                return res.status(500).json({ Message: "Error inside server" });
              }
              if (result.length > 0) {
                const assetInstallValue = result[0].assetinstall;
                return res.json({
                  status: "errorsoftware",
                  message: "Software already exists.",
                  assetInstallValue: assetInstallValue,
                });
              } else {
                const del = "DELETE FROM pc_install_sw WHERE pcinstall = ? ";
                db.query(del, [req.body.hw_assetnumber], (err, result) => {
                  if (err) {
                    console.error(
                      "Error deleting existing software installations:",
                      err
                    );
                    return res
                      .status(500)
                      .json({ Message: "Error inside server" });
                  }
                  const arr = req.body.hw_softwareinstall;
                  const midtable =
                    "INSERT INTO pc_install_sw (`pcinstall`, `swinstall`) VALUES (?, ?)";
                  for (let sw of arr) {
                    db.query(
                      midtable,
                      [req.body.hw_assetnumber, sw],
                      (err, result) => {
                        if (err) {
                          console.error("Error inserting software:", err);
                        }
                      }
                    );
                  }
                  res.json({
                    status: "success",
                    message: "Asset updated successfully.",
                  });
                });
              }
            }
          );
        }
      });
    }
  });
});
app.put("/update-accessories/:id", (req, res) => {
  const requiredFields = [
    `acc_type`,
    `acc_detail`,
    `acc_serialnumber`,
    `acc_assetinstall`,
    `acc_location`,
    `acc_department`,
    `acc_price`,
    `acc_receivedate`,
    "acc_invoicenumber",
    "acc_ponumber",
  ];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  const sql =
    "UPDATE accessories SET `acc_type`=?, `acc_detail`=?, `acc_serialnumber`=?, `acc_assetinstall`=?, `acc_location`=?, `acc_department`=?, `acc_price`=?, `acc_receivedate`=?, `acc_invoicenumber`=?, `acc_ponumber`=? WHERE id=?";
  const id = req.params.id;
  db.query(
    sql,
    [
      req.body.acc_type,
      req.body.acc_detail,
      req.body.acc_serialnumber,
      req.body.acc_assetinstall,
      req.body.acc_location,
      req.body.acc_department,
      req.body.acc_price,
      req.body.acc_receivedate,
      req.body.acc_invoicenumber,
      req.body.acc_ponumber,
      id,
    ],
    (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    }
  );
});
app.put("/update-software/:id", (req, res) => {
  const requiredFields = [
    `sw_assetnumber`,
    `sw_name`,
    `sw_serialnumber`,
    `sw_softwarekey`,
    `sw_user`,
    `sw_location`,
    `sw_price`,
    `sw_receivedate`,
    `sw_invoicenumber`,
    `sw_ponumber`,
  ];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  const sqlCheckDuplicate =
    "SELECT COUNT(*) AS count FROM software WHERE REPLACE(sw_assetnumber, '-', '') = ? AND id != ?";
  const assetnum = req.body.sw_assetnumber.replace(/\W/g, "");
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
        "UPDATE software SET `sw_assetnumber`=?, `sw_name`=?, `sw_serialnumber`=?, `sw_softwarekey`=?, `sw_user`=?, `sw_location`=?, `sw_price`=?, `sw_receivedate`=?, `sw_invoicenumber`=?, `sw_ponumber`=? WHERE id=?";
      db.query(
        sql,
        [
          req.body.sw_assetnumber,
          req.body.sw_name,
          req.body.sw_serialnumber,
          req.body.sw_softwarekey,
          req.body.sw_user,
          req.body.sw_location,
          req.body.sw_price,
          req.body.sw_receivedate,
          req.body.sw_invoicenumber,
          req.body.sw_ponumber,
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
app.put("/update-yearlysoftware/:id", (req, res) => {
  const requiredFields = [
    `ys_name`,
    `ys_serialnumber`,
    `ys_assetinstall`,
    `ys_receivedate`,
    `ys_expiredate`,
    `ys_price`,
    `ys_invoicenumber`,
    `ys_ponumber`,
  ];
  for (const field of requiredFields) {
    if (req.body[field] === undefined || req.body[field] === null) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  if (new Date(req.body.ys_receivedate) > new Date(req.body.ys_expiredate)) {
    return res.json({
      status: "errordate",
      Message: "receivedate cannot be after expiredate.",
    });
  }
  const sql =
    "UPDATE yearlysoftware SET `ys_name`=?, `ys_serialnumber`=?,`ys_assetinstall`=?, `ys_receivedate`=?, `ys_expiredate`=?, `ys_price`=?, `ys_invoicenumber`=?, `ys_ponumber`=? WHERE id=?";
  const id = req.params.id;
  db.query(
    sql,
    [
      req.body.ys_name,
      req.body.ys_serialnumber,
      req.body.ys_assetinstall,
      req.body.ys_receivedate,
      req.body.ys_expiredate,
      req.body.ys_price,
      req.body.ys_invoicenumber,
      req.body.ys_ponumber,
      id,
    ],
    (err, result) => {
      if (err) return res.json({ Message: "Error inside server" });
      return res.json(result);
    }
  );
});
app.put("/update-amortized/:id", (req, res) => {
  const id = req.params.id;
  const requiredFields = [
    `hw_assetnumber`,
    `hw_brand`,
    `hw_model`,
    `hw_user`,
    `hw_location`,
    `hw_department`,
    `hw_spec`,
    `hw_serialnumber`,
    `hw_price`,
    `hw_receivedate`,
    `hw_invoicenumber`,
    `hw_ponumber`,
    `hw_amortizeddate`,
  ];
  for (const field of requiredFields) {
    if (!req.body[field]) {
      return res.status(400).json({ Message: `${field} is required.` });
    }
  }
  const assetnum = req.body.hw_assetnumber.replace(/\W/g, "");
  const sqlCheckDuplicateAsset =
    "SELECT COUNT(*) AS count FROM hardware WHERE REPLACE(hw_assetnumber, '-', '') = ?;";
  db.query(sqlCheckDuplicateAsset, [assetnum, id], (err, result) => {
    if (err) {
      console.error("Error checking duplicate asset:", err);
      return res.status(500).json({ Message: "Error inside server" });
    }
    const count = result[0].count;
    if (count > 0) {
      return res.json({
        status: "error",
        message: "Asset Number already exists.",
      });
    } else {
      const updateSql =
        "UPDATE hardware SET `hw_assetnumber`=?, `hw_brand`=?, `hw_model`=?, `hw_user`=?, `hw_location`=?, `hw_department`=?, `hw_spec`=?, `hw_serialnumber`=?, `hw_price`=?, `hw_receivedate`=?, `hw_invoicenumber`=?, `hw_ponumber`=?, `hw_amortizeddate`=? WHERE id=?";
      const values = [
        req.body.hw_assetnumber,
        req.body.hw_brand,
        req.body.hw_model,
        req.body.hw_user,
        req.body.hw_location,
        req.body.hw_department,
        req.body.hw_spec,
        req.body.hw_serialnumber,
        req.body.hw_price,
        req.body.hw_receivedate,
        req.body.hw_invoicenumber,
        req.body.hw_ponumber,
        req.body.hw_amortizeddate,
        id,
      ];
      db.query(updateSql, values, (err, result) => {
        if (err) {
          console.error("Error updating hardware asset:", err);
          return res.status(500).json({ Message: "Error inside server" });
        }
        const software = req.body.hw_softwareinstall;
        if (software == "None Install") {
          const del = "DELETE FROM pc_install_sw WHERE pcinstall = ? ";
          db.query(del, [req.body.hw_assetnumber], (err, result) => {
            if (err) {
              console.error(
                "Error deleting existing software installations:",
                err
              );
              return res.status(500).json({ Message: "Error inside server" });
            }
            res.json({
              status: "success",
              message: "Asset updated successfully.",
            });
          });
        } else {
          const sqlCheckDuplicateSoftware =
            "SELECT * FROM pc_install_sw WHERE swinstall IN (?) AND pcinstall != ?";
          db.query(
            sqlCheckDuplicateSoftware,
            [software, req.body.hw_assetnumber],
            (err, result) => {
              if (err) {
                console.error("Error checking duplicate software:", err);
                return res.status(500).json({ Message: "Error inside server" });
              }
              if (result.length > 0) {
                const assetInstallValue = result[0].assetinstall;
                return res.json({
                  status: "errorsoftware",
                  message: "Software already exists.",
                  assetInstallValue: assetInstallValue,
                });
              } else {
                const del = "DELETE FROM pc_install_sw WHERE pcinstall = ? ";
                db.query(del, [req.body.hw_assetnumber], (err, result) => {
                  if (err) {
                    console.error(
                      "Error deleting existing software installations:",
                      err
                    );
                    return res
                      .status(500)
                      .json({ Message: "Error inside server" });
                  }
                  const arr = req.body.hw_softwareinstall;
                  const midtable =
                    "INSERT INTO pc_install_sw (`pcinstall`, `swinstall`) VALUES (?, ?)";
                  for (let sw of arr) {
                    db.query(
                      midtable,
                      [req.body.hw_assetnumber, sw],
                      (err, result) => {
                        if (err) {
                          console.error("Error inserting software:", err);
                        }
                      }
                    );
                  }
                  res.json({
                    status: "success",
                    message: "Asset updated successfully.",
                  });
                });
              }
            }
          );
        }
      });
    }
  });
});
//Delete
app.delete("/delete-hardware/:id", (req, res) => {
  const sql = "DELETE FROM hardware WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.delete("/delete-accessories/:id", (req, res) => {
  const sql = "DELETE FROM accessories WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.delete("/delete-software/:id", (req, res) => {
  const sql = "DELETE FROM software WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.delete("/delete-yearlysoftware/:id", (req, res) => {
  const sql = "DELETE FROM yearlysoftware WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.delete("/delete-amortized/:id", (req, res) => {
  const sql = "DELETE FROM hardware WHERE id = ?";
  const id = req.params.id;

  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});

//Dashboard API
//Get total count
app.get("/hardwaretotal", (req, res) => {
  const sql =
    "SELECT COUNT(id) AS hardware FROM hardware WHERE hw_amortized = False";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.get("/accessoriestotal", (req, res) => {
  const sql = "SELECT COUNT(id) AS accessories	FROM accessories";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.get("/softwaretotal", (req, res) => {
  const sql = "SELECT COUNT(id) AS software FROM software";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.get("/yearlysoftwaretotal", (req, res) => {
  const sql = "SELECT COUNT(id) AS yearlysoftware FROM yearlysoftware";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
app.get("/amortizedtotal", (req, res) => {
  const sql =
    "SELECT COUNT(id) AS hardware FROM hardware WHERE hw_amortized = True";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result);
  });
});
//Get total price
app.get("/hardwareprice", (req, res) => {
  const sql = "SELECT sum(hw_price) AS hw_price FROM hardware";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result[0]);
  });
});
app.get("/accessoriesprice", (req, res) => {
  const sql = "SELECT sum(acc_price) AS acc_price FROM accessories";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result[0]);
  });
});
app.get("/softwareprice", (req, res) => {
  const sql = "SELECT sum(sw_price) AS sw_price FROM software";
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result[0]);
  });
});
app.get("/yearlysoftwareprice", (req, res) => {
  const currentDate = new Date().toISOString().split("T")[0];
  const sql = `SELECT SUM(ys_price) AS ys_price FROM yearlysoftware WHERE ys_expiredate >= '${currentDate}'`;
  db.query(sql, (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    return res.json(result[0]);
  });
});

//Sup API
//Get assetnumber + name
app.get("/hardware-user", (req, res) => {
  const sql = "SELECT hw_assetnumber,hw_user FROM hardware";
  db.query(sql, (err, result) => {
    if (err) {
      console.error("Error executing query:", err);
      return res.json({ Message: "Error executing query" });
    }
    const assets = result.map((row) => ({
      hwassetnumber: row.hw_assetnumber,
      user: row.hw_user,
    }));
    return res.json(assets);
  });
});
app.get("/software-name", (req, res) => {
  const sql = "SELECT `sw_assetnumber`, `sw_name` FROM software LEFT JOIN pc_install_sw ON sw_assetnumber = swinstall WHERE swinstall  is null";
  db.query(sql, (err, result) => {
    if (err) {
      console.error("Error executing query:", err);
      return res.json({ Message: "Error executing query" });
    }
    const assets = result.map((row) => ({
      sw_assetnumber: row.sw_assetnumber,
      sw_name: row.sw_name,
    }));
    return res.json(assets);
  });
});
//Amortized
app.put("/hardware-amortized/:id", (req, res) => {
  const id = req.params.id;
  const sql =
    "UPDATE hardware SET `hw_amortizeddate` = DATE(CURRENT_TIMESTAMP()), `hw_amortized` = True WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) return res.json(err);

    return res.json(result);
  });
});
app.post("/amortized-hardware/:id", (req, res) => {
  const id = req.params.id;
  const sql =
    "UPDATE hardware SET `hw_amortizeddate` = null, `hw_amortized` = False WHERE id = ?";
  db.query(sql, [id], (err, result) => {
    if (err) return res.json(err);

    return res.json(result);
  });
});
//midtable
app.get("/hw-softwareinstall/:id", (req, res) => {
  const id = req.params.id;
  const sql =
    "SELECT GROUP_CONCAT(swinstall SEPARATOR ', ') as softwareinstall FROM hardware LEFT JOIN pc_install_sw ON hw_assetnumber = pcinstall WHERE id = ? GROUP BY hw_assetnumber";
  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    if (result.length === 0 || result[0].softwareinstall === null) {
      return res.send(["None Install"]);
    } else {
      const softwareinstallData = result[0].softwareinstall;
      return res.send(softwareinstallData);
    }
  });
});
//midtableselect
app.get("/select-softwareinstall/:id", (req, res) => {
  const id = req.params.id;
  const sql =
    "SELECT GROUP_CONCAT(swinstall SEPARATOR ', ') as softwareinstall FROM hardware JOIN pc_install_sw ON hw_assetnumber = pcinstall WHERE id = ? GROUP BY hw_assetnumber";
  db.query(sql, [id], (err, result) => {
    if (err) return res.json({ Message: "Error inside server" });
    const softwareinstallData = result[0].softwareinstall;
    return res.send(softwareinstallData);
  });
});

app.listen(process.env.PORT, () => {
  console.log("Server is running");
});
