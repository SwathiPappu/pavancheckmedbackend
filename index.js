// labby-labs\backEnd\index.js
require("dotenv").config(); // Make sure .env is in the correct location
const express = require("express");
const mysql = require("mysql");
const bodyParser = require("body-parser");
const cors = require("cors");
const bcrypt = require("bcrypt");
const saltRounds = 10;
const fs = require("fs");
const path = require("path");
const plainTextPassword = "admin123";
const app = express();
const port = 3000; // Use PORT from .env or default to 3000

app.use(cors({
  origin: 'https://checkmedqrmodule.netlify.app',
  methods: ['GET', 'POST', 'PUT', 'DELETE'],
  credentials: true,
}));
app.use(bodyParser.json());

// const db = mysql.createConnection({
//   host: "sql12.freesqldatabase.com",
//   user: "sql12714792",
//   password: "SVdGlRSCJ9",
//   database: "sql12714792",
// });
const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME,
  ssl: {
    ca: fs.readFileSync(path.resolve(__dirname, "DigiCertGlobalRootCA.crt.pem")),
  },
});

app.use((req, res, next) => {
  res.setHeader("Cache-Control", "no-store, must-revalidate");
  next();
});
db.connect((err) => {
  if (err) {
    console.error("Error connecting to MySQL database:", err);
    console.log("Please check your database credentials and try again.");
    process.exit(1);
  }
  console.log("Connected to MySQL database.");
});

db.query("SELECT * FROM admins WHERE username = 'Admin'", (err, results) => {
  if (err) {
    console.error("Error checking for existing Admin user:", err);
    return;
  }

  if (results.length === 0) {
    // If Admin user does not exist, create it
    bcrypt.hash(plainTextPassword, saltRounds, (err, hash) => {
      if (err) {
        console.error("Error hashing password:", err);
        return;
      }

      const sql = "INSERT INTO admins (username, password) VALUES (?, ?)";
      db.query(sql, ["Admin", hash], (err, result) => {
        if (err) {
          console.error("Error inserting admin credentials:", err);
          return;
        }
        console.log("Admin credentials stored successfully.");
      });
    });
  } else {
    console.log("Admin user already exists.");
  }
});

app.post("/api/admin/login", (req, res) => {
  const { username, password } = req.body;
  console.log("Received username:", username);
  console.log("Received password:", password);

  const sql = "SELECT * FROM admins WHERE username = ?";
  db.query(sql, [username], (err, results) => {
    if (err) {
      console.error("Error verifying admin credentials:", err);
      res.status(500).json({ error: "Internal Server Error" });
      return;
    }
    console.log("Query results:", results);

    if (results.length === 0) {
      res.status(401).json({ error: "Invalid credentials" });
      return;
    }

    const hashedPassword = results[0].password;
    bcrypt.compare(password, hashedPassword, (err, isMatch) => {
      if (err) {
        console.error("Error comparing passwords:", err);
        res.status(500).json({ error: "Internal Server Error" });
        return;
      }
      if (!isMatch) {
        res.status(401).json({ error: "Invalid credentials" });
        return;
      }
      res.status(200).json({ message: "Login successful" });
    });
  });
});

app.post("/api/admin/change-password", (req, res) => {
  const { oldPassword, newPassword } = req.body;
  const username = "Admin"; // Assuming we only have one admin for simplicity

  const sql = "SELECT * FROM admins WHERE username = ?";
  db.query(sql, [username], (err, results) => {
    if (err) {
      console.error("Error fetching admin details:", err);
      res.status(500).json({ error: "Internal Server Error" });
      return;
    }

    if (results.length === 0) {
      res.status(404).json({ error: "Admin not found" });
      return;
    }

    const hashedPassword = results[0].password;
    bcrypt.compare(oldPassword, hashedPassword, (err, isMatch) => {
      if (err) {
        console.error("Error comparing passwords:", err);
        res.status(500).json({ error: "Internal Server Error" });
        return;
      }

      if (!isMatch) {
        res.status(401).json({ error: "Incorrect old password" });
        return;
      }

      bcrypt.hash(newPassword, saltRounds, (err, newHash) => {
        if (err) {
          console.error("Error hashing new password:", err);
          res.status(500).json({ error: "Internal Server Error" });
          return;
        }

        const updateSql = "UPDATE admins SET password = ? WHERE username = ?";
        db.query(updateSql, [newHash, username], (err, result) => {
          if (err) {
            console.error("Error updating password:", err);
            res.status(500).json({ error: "Internal Server Error" });
            return;
          }
          res.status(200).json({ message: "Password updated successfully" });
        });
      });
    });
  });
});

app.get("/api/user/:phoneNumber", (req, res) => {
  const phoneNumber = req.params.phoneNumber;
  const sql = "SELECT id FROM users WHERE phoneNumber = ?";
  db.query(sql, [phoneNumber], (err, result) => {
    if (err) {
      console.error("Error retrieving userId:", err);
      res.status(500).json({ error: "Internal Server Error" });
      return;
    }
    if (result.length === 0) {
      res.status(404).json({ error: "User not found" });
      return;
    }
    const userId = result[0].id;
    res.status(200).json({ userId });
  });
});

// API to update ReportsTaken status for a user
app.put("/api/users/:id", (req, res) => {
  const userId = req.params.id;
  const { ReportsTaken, additionalInfo } = req.body;
  const sql =
    "UPDATE users SET ReportsTaken = ?, additionalInfo = ? WHERE id = ?";
  db.query(sql, [ReportsTaken, additionalInfo, userId], (err, result) => {
    if (err) {
      console.error(
        "Error updating ReportsTaken status and additionalInfo:",
        err
      );
      res.status(500).json({ error: "Internal Server Error" });
      return;
    }
    console.log(
      `ReportsTaken status and additionalInfo updated for user with id ${userId}`
    );
    res.status(200).json({
      message: "ReportsTaken status and additionalInfo updated successfully",
    });
  });
});

// API to retrieve ReportsTaken status for a user
app.get("/api/users/:id/reports-taken", (req, res) => {
  const userId = req.params.id;
  const sql = "SELECT ReportsTaken, additionalInfo FROM users WHERE id = ?";
  db.query(sql, [userId], (err, result) => {
    if (err) {
      console.error(
        "Error retrieving ReportsTaken status and additionalInfo:",
        err
      );
      res.status(500).json({ error: "Internal Server Error" });
      return;
    }
    if (result.length === 0) {
      res.status(404).json({ error: "User not found" });
      return;
    }
    const { ReportsTaken, additionalInfo } = result[0];
    res.status(200).json({ ReportsTaken, additionalInfo });
  });
});

app.post("/api/user", (req, res) => {
  const { phoneNumber } = req.body;

  db.query(
    "SELECT * FROM users WHERE phoneNumber = ?",
    [phoneNumber],
    (err, results) => {
      if (err) {
        return res.status(500).send(err);
      }

      if (results.length > 0) {
        res.send(results[0]);
      } else {
        const newUser = {
          phoneNumber: phoneNumber,
          patientName: "",
          employeeId: "",
          email: "",
          age: "",
          gender: "",
          packages:"",
        };
        db.query("INSERT INTO users SET ?", newUser, (err, result) => {
          if (err) {
            return res.status(500).send(err);
          }
          newUser.id = result.insertId;
          res.send(newUser);
        });
      }
    }
  );
});

app.post("/api/user/update", (req, res) => {
  const {
    phoneNumber,
    patientName,
    employeeId,
    email,
    age,
    gender,
    package: selectedPackage,
    bookingId,
    city,
    companyName,
  } = req.body;

  const sql = `
    UPDATE users 
    SET 
      patientName = ?, 
      employeeId = ?, 
      email = ?, 
      age = ?, 
      gender = ?, 
      package = ?, 
      bookingId = ?, 
      city = ?, 
      companyName = ? 
    WHERE phoneNumber = ?
  `;
  const values = [
    patientName,
    employeeId,
    email,
    age,
    gender,
    selectedPackage,
    bookingId,
    city,
    companyName,
    phoneNumber,
  ];
  db.query(sql, values, (err, result) => {
    if (err) {
      console.error("Error updating user details:", err);
      return res.status(500).json({ error: "Internal Server Error" });
    }
    res.json({ message: "User details updated successfully." });
  });
});

// Route to fetch all users
app.get("/api/users", (req, res) => {
  console.log("Received request for /api/users");
  const sql = "SELECT * FROM users";
  db.query(sql, (err, results) => {
    if (err) {
      console.error("Error retrieving users:", err);
      res.status(500).json({ error: "Internal Server Error" });
      return;
    }
    res.status(200).json(results);
  });
});

app.get("/api/qr-reports", (req, res) => {
  console.log("Received request for /api/qr-reports");
  const { city, companyName } = req.query;
  let sql = "SELECT * FROM generateqr WHERE 1=1";
  const params = [];

  if (city) {
    sql += " AND city = ?";
    params.push(city);
  }

  if (companyName) {
    sql += " AND companyName = ?";
    params.push(companyName);
  }

  db.query(sql, params, (err, results) => {
    if (err) {
      console.error("Error retrieving QR reports:", err);
      res.status(500).json({ error: "Internal Server Error" });
      return;
    }
    res.status(200).json(results);
  });
});

app.get("/api/packages", (req, res) => {
  const { city, companyName } = req.query;
  const sql =
    "SELECT package1, package2, package3, package4 FROM generateqr WHERE city = ? AND companyName = ?";
  db.query(sql, [city, companyName], (err, results) => {
    if (err) {
      console.error("Error retrieving packages:", err);
      res.status(500).json({ error: "Internal Server Error" });
      return;
    }
    if (results.length === 0) {
      res.status(404).json({ error: "Packages not found" });
      return;
    }
    const packages = Object.values(results[0]).filter((pkg) => pkg);
    res.status(200).json(packages);
  });
});

// Route to fetch filtered users based on various criteria
app.get("/api/users/filter", (req, res) => {
  const {
    phoneNumber,
    patientName,
    employeeId,
    reportsPending,
    city,
    companyName,
  } = req.query;
  let sql = "SELECT * FROM users WHERE 1=1";
  const params = [];

  if (phoneNumber) {
    sql += " AND phoneNumber = ?";
    params.push(phoneNumber);
  }

  if (patientName) {
    sql += " AND patientName LIKE ?";
    params.push(`%${patientName}%`);
  }

  if (employeeId) {
    sql += " AND employeeId = ?";
    params.push(employeeId);
  }

  if (reportsPending !== undefined && reportsPending !== "") {
    sql += " AND ReportsTaken = ?";
    params.push(reportsPending);
  }

  if (city) {
    sql += " AND city = ?";
    params.push(city);
  }

  if (companyName) {
    sql += " AND companyName = ?";
    params.push(companyName);
  }

  db.query(sql, params, (err, results) => {
    if (err) {
      console.error("Error retrieving filtered users:", err);
      res.status(500).json({ error: "Internal Server Error" });
      return;
    }
    res.status(200).json(results);
  });
});

app.post("/api/generateqr", (req, res) => {
  const { city, companyName, package1, package2, package3, package4 } =
    req.body;

  const sql =
    "INSERT INTO generateqr (city, companyName, package1, package2, package3, package4) VALUES (?, ?, ?, ?, ?, ?)";
  db.query(
    sql,
    [city, companyName, package1, package2, package3, package4],
    (err, result) => {
      if (err) {
        console.error("Error inserting data into generateqr:", err);
        res.status(500).json({ error: "Internal Server Error" });
        return;
      }
      res
        .status(200)
        .json({ message: "Data inserted successfully", id: result.insertId });
    }
  );
});

//api for dashboard
// Fetch dashboard data
app.get("/api/users/dashboard-data", (req, res) => {
  const totalUsersQuery = "SELECT COUNT(*) AS totalUsers FROM users";
  const samplesCollectedQuery =
    "SELECT COUNT(*) AS samplesCollected FROM users WHERE reportsTaken = 1";
  const samplesPendingQuery =
    "SELECT COUNT(*) AS samplesPending FROM users WHERE reportsTaken = 0";

  const maleUnder30Query = `
    SELECT 
      COUNT(*) AS amt,
      SUM(CASE WHEN reportsTaken = 1 THEN 1 ELSE 0 END) AS Done,
      SUM(CASE WHEN reportsTaken = 0 THEN 1 ELSE 0 END) AS Pending
    FROM users
    WHERE gender = 'Male' AND age < 30
  `;

  const femaleUnder30Query = `
    SELECT 
      COUNT(*) AS amt,
      SUM(CASE WHEN reportsTaken = 1 THEN 1 ELSE 0 END) AS Done,
      SUM(CASE WHEN reportsTaken = 0 THEN 1 ELSE 0 END) AS Pending
    FROM users
    WHERE gender = 'Female' AND age < 30
  `;

  const maleOver30Query = `
    SELECT 
      COUNT(*) AS amt,
      SUM(CASE WHEN reportsTaken = 1 THEN 1 ELSE 0 END) AS Done,
      SUM(CASE WHEN reportsTaken = 0 THEN 1 ELSE 0 END) AS Pending
    FROM users
    WHERE gender = 'Male' AND age >= 30
  `;

  const femaleOver30Query = `
    SELECT 
      COUNT(*) AS amt,
      SUM(CASE WHEN reportsTaken = 1 THEN 1 ELSE 0 END) AS Done,
      SUM(CASE WHEN reportsTaken = 0 THEN 1 ELSE 0 END) AS Pending
    FROM users
    WHERE gender = 'Female' AND age >= 30
  `;

  db.query(totalUsersQuery, (error, totalUsersResult) => {
    if (error) {
      console.error("Error fetching total users:", error);
      return res.status(500).json({ error: "Error fetching total users" });
    }

    db.query(samplesCollectedQuery, (error, samplesCollectedResult) => {
      if (error) {
        console.error("Error fetching samples collected:", error);
        return res
          .status(500)
          .json({ error: "Error fetching samples collected" });
      }

      db.query(samplesPendingQuery, (error, samplesPendingResult) => {
        if (error) {
          console.error("Error fetching samples pending:", error);
          return res
            .status(500)
            .json({ error: "Error fetching samples pending" });
        }

        db.query(maleUnder30Query, (error, maleUnder30Result) => {
          if (error) {
            console.error("Error fetching male under 30:", error);
            return res
              .status(500)
              .json({ error: "Error fetching male under 30" });
          }

          db.query(femaleUnder30Query, (error, femaleUnder30Result) => {
            if (error) {
              console.error("Error fetching female under 30:", error);
              return res
                .status(500)
                .json({ error: "Error fetching female under 30" });
            }

            db.query(maleOver30Query, (error, maleOver30Result) => {
              if (error) {
                console.error("Error fetching male over 30:", error);
                return res
                  .status(500)
                  .json({ error: "Error fetching male over 30" });
              }

              db.query(femaleOver30Query, (error, femaleOver30Result) => {
                if (error) {
                  console.error("Error fetching female over 30:", error);
                  return res
                    .status(500)
                    .json({ error: "Error fetching female over 30" });
                }

                res.json({
                  totalUsers: totalUsersResult[0].totalUsers,
                  samplesCollected: samplesCollectedResult[0].samplesCollected,
                  samplesPending: samplesPendingResult[0].samplesPending,
                  maleUnder30: maleUnder30Result[0],
                  femaleUnder30: femaleUnder30Result[0],
                  maleOver30: maleOver30Result[0],
                  femaleOver30: femaleOver30Result[0],
                });
              });
            });
          });
        });
      });
    });
  });
});

app.listen(port, () => {
  console.log(`Server running on port ${port}`);
});
