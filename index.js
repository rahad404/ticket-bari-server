require("dotenv").config();

const express = require("express");
const cors = require("cors");
const { MongoClient, ServerApiVersion, ObjectId } = require("mongodb");
const { createRemoteJWKSet, jwtVerify } = require("jose-cjs");
// const Stripe = require("stripe");

const app = express();

// middleware
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: false }));

const port = process.env.PORT || 5000;
const uri = process.env.MONGODB_URI;
// const stripe = Stripe(process.env.STRIPE_SECRET_KEY);

const client = new MongoClient(uri, {
   serverApi: {
      version: ServerApiVersion.v1,
      strict: true,
      deprecationErrors: true,
   },
});

// JWT (BetterAuth JWKS)
const JWKS = createRemoteJWKSet(new URL(`${process.env.CLIENT_URL}/api/auth/jwks`));

// verify that a valid token was sent
const verifyToken = async (req, res, next) => {
   const authHeader = req?.headers.authorization;
   if (!authHeader) {
      return res.status(401).json({ message: "unauthorized" });
   }
   const token = authHeader.split(" ")[1];

   if (!token) {
      return res.status(401).json({ message: "unauthorized" });
   }

   try {
      const { payload } = await jwtVerify(token, JWKS);
      req.user = payload; // NOTE: confirm the email claim path matches your BetterAuth JWT
      // (e.g. payload.email). Adjust req.user.email references below if your
      // payload nests it differently, like payload.user.email.
      next();
   } catch (error) {
      console.error(error);
      return res.status(401).json({ message: "unauthorized" });
   }
};

async function run() {
   try {
      await client.connect();
      console.log("Connected successfully to MongoDB!");

      const db = client.db("ticketbari");
      const userCollection = db.collection("user"); // singular: matches BetterAuth default collection name
      const ticketCollection = db.collection("tickets");
      const bookingCollection = db.collection("bookings");
      const paymentCollection = db.collection("payments");

      // ROLE MIDDLEWARE -----------------------------
      // must be used AFTER verifyToken, since it relies on req.user being set
      const verifyAdmin = async (req, res, next) => {
         try {
            const email = req.user?.email;
            const user = await userCollection.findOne({ email });
            if (!user || user.role !== "admin") {
               return res.status(403).json({ message: "forbidden access" });
            }
            next();
         } catch (error) {
            console.error("verifyAdmin error:", error);
            res.status(500).json({ message: "Server error" });
         }
      };

      const verifyVendor = async (req, res, next) => {
         try {
            const email = req.user?.email;
            const user = await userCollection.findOne({ email });
            if (!user || user.role !== "vendor") {
               return res.status(403).json({ message: "forbidden access" });
            }
            if (user.isFraud) {
               return res.status(403).json({ message: "Your vendor account has been marked as fraud." });
            }
            req.vendorUser = user;
            next();
         } catch (error) {
            console.error("verifyVendor error:", error);
            res.status(500).json({ message: "Server error" });
         }
      };

      app.get("/", (req, res) => {
         res.send("TicketBari server is running!");
      });

      // USER ROUTES
      // ===================================================================

      // get all users (admin - Manage Users page)
      app.get("/users", verifyToken, verifyAdmin, async (req, res) => {
         try {
            const users = await userCollection.find().sort({ createdAt: -1 }).toArray();
            res.status(200).json(users);
         } catch (error) {
            console.error("Error fetching users:", error);
            res.status(500).json({ message: "Failed to fetch users." });
         }
      });

      // get a user's role + fraud flag (used for route protection / dashboard redirect)
      app.get("/users/role/:email", verifyToken, async (req, res) => {
         try {
            const { email } = req.params;
            const user = await userCollection.findOne({ email }, { projection: { role: 1, isFraud: 1 } });
            if (!user) return res.status(404).json({ message: "User not found." });
            res.status(200).json({ role: user.role || "user", isFraud: user.isFraud || false });
         } catch (error) {
            console.error("Error fetching user role:", error);
            res.status(500).json({ message: "Failed to fetch user role." });
         }
      });








      // ===================================================================
      // FALLBACK HANDLERS
      // ===================================================================

      app.use((req, res) => {
         res.status(404).json({ message: "Route not found" });
      });

      app.use((err, req, res, next) => {
         console.error(err.stack);
         res.status(500).json({ message: "Something went wrong!" });
      });

      app.listen(port, () => {
         console.log(`TicketBari server listening on port ${port}`);
      });
   } catch (error) {
      console.error("Database connection failed:", error);
      process.exit(1);
   }
}

run().catch(console.dir);