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

      // get a single user's full profile
      app.get("/users/:email", verifyToken, async (req, res) => {
         try {
            const { email } = req.params;
            const user = await userCollection.findOne({ email });
            if (!user) return res.status(404).json({ message: "User not found." });
            res.status(200).json(user);
         } catch (error) {
            console.error("Error fetching user:", error);
            res.status(500).json({ message: "Failed to fetch user." });
         }
      });

      // promote a user to admin
      app.patch("/users/admin/:id", verifyToken, verifyAdmin, async (req, res) => {
         try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid User ID" });

            const result = await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { role: "admin" } });
            if (result.matchedCount === 0) return res.status(404).json({ message: "User not found." });

            res.status(200).json({ success: true, message: "User promoted to admin." });
         } catch (error) {
            console.error("Error making admin:", error);
            res.status(500).json({ message: "Failed to update user role." });
         }
      });

      // promote a user to vendor
      app.patch("/users/vendor/:id", verifyToken, verifyAdmin, async (req, res) => {
         try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid User ID" });

            const result = await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { role: "vendor" } });
            if (result.matchedCount === 0) return res.status(404).json({ message: "User not found." });

            res.status(200).json({ success: true, message: "User promoted to vendor." });
         } catch (error) {
            console.error("Error making vendor:", error);
            res.status(500).json({ message: "Failed to update user role." });
         }
      });

      // mark a vendor as fraud -> hides all of their tickets + blocks future ticket adds
      app.patch("/users/fraud/:id", verifyToken, verifyAdmin, async (req, res) => {
         try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid User ID" });

            const targetUser = await userCollection.findOne({ _id: new ObjectId(id) });
            if (!targetUser) return res.status(404).json({ message: "User not found." });
            if (targetUser.role !== "vendor") {
               return res.status(400).json({ message: "Only vendors can be marked as fraud." });
            }

            await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: { isFraud: true } });

            // hide all tickets belonging to this vendor from public listings
            await ticketCollection.updateMany({ vendorEmail: targetUser.email }, { $set: { isHidden: true } });

            res.status(200).json({ success: true, message: "Vendor marked as fraud and their tickets are now hidden." });
         } catch (error) {
            console.error("Error marking fraud:", error);
            res.status(500).json({ message: "Failed to mark vendor as fraud." });
         }
      });

      // update own profile (name, image)
      app.patch("/users/:id", verifyToken, async (req, res) => {
         try {
            const id = req.params.id;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid user ID" });

            const targetUser = await userCollection.findOne({ _id: new ObjectId(id) });
            if (!targetUser) return res.status(404).json({ message: "User not found" });
            if (targetUser.email !== req.user.email) {
               return res.status(403).json({ message: "forbidden access" });
            }

            const { name, image } = req.body;
            const fields = {};
            if (name !== undefined && name !== "") fields.name = name;
            if (image !== undefined && image !== "") fields.image = image;

            if (Object.keys(fields).length === 0) {
               return res.status(400).json({ message: "No valid fields provided to update" });
            }

            const result = await userCollection.updateOne({ _id: new ObjectId(id) }, { $set: fields });
            res.status(200).json({ success: true, message: "Profile updated successfully", result });
         } catch (error) {
            console.error("Error updating user:", error);
            res.status(500).json({ message: "Server error" });
         }
      });



      // TICKET ROUTES
      // ===================================================================

      // vendor adds a new ticket (verification status starts as "pending")
      app.post("/tickets", verifyToken, verifyVendor, async (req, res) => {
         try {
            const ticketData = req.body;

            const newTicket = {
               ...ticketData,
               price: Number(ticketData.price),
               quantity: Number(ticketData.quantity),
               verificationStatus: "pending",
               isAdvertised: false,
               isHidden: false,
               createdAt: new Date(),
            };

            const result = await ticketCollection.insertOne(newTicket);
            res.status(201).json({ success: true, message: "Ticket submitted for review.", ticketId: result.insertedId });
         } catch (error) {
            console.error("Error adding ticket:", error);
            res.status(500).json({ message: "Failed to add ticket." });
         }
      });

      // public: approved, non-hidden tickets with search / filter / sort / pagination ("All Tickets" page)
      app.get("/tickets", async (req, res) => {
         try {
            const { search, from, to, transportType, sort, page = 1, limit = 9 } = req.query;
            const query = { verificationStatus: "approved", isHidden: { $ne: true } };

            if (from?.trim()) query.from = { $regex: from.trim(), $options: "i" };
            if (to?.trim()) query.to = { $regex: to.trim(), $options: "i" };
            if (search?.trim()) {
               query.$or = [
                  { from: { $regex: search.trim(), $options: "i" } },
                  { to: { $regex: search.trim(), $options: "i" } },
                  { title: { $regex: search.trim(), $options: "i" } },
               ];
            }
            if (transportType?.trim() && transportType !== "all") {
               query.transportType = transportType;
            }

            let sortQuery = { createdAt: -1 };
            if (sort === "price_asc") sortQuery = { price: 1 };
            if (sort === "price_desc") sortQuery = { price: -1 };

            const pageNum = Number(page) || 1;
            const limitNum = Number(limit) || 9;
            const skip = (pageNum - 1) * limitNum;

            const tickets = await ticketCollection
               .find(query)
               .sort(sortQuery)
               .skip(skip)
               .limit(limitNum)
               .toArray();

            res.status(200).json(tickets);
         } catch (error) {
            console.error("Error fetching tickets:", error);
            res.status(500).json({ message: "Failed to fetch tickets." });
         }
      });

      // public: total count for the same filters above (used for pagination controls)
      app.get("/tickets-count", async (req, res) => {
         try {
            const { search, from, to, transportType } = req.query;
            const query = { verificationStatus: "approved", isHidden: { $ne: true } };

            if (from?.trim()) query.from = { $regex: from.trim(), $options: "i" };
            if (to?.trim()) query.to = { $regex: to.trim(), $options: "i" };
            if (search?.trim()) {
               query.$or = [
                  { from: { $regex: search.trim(), $options: "i" } },
                  { to: { $regex: search.trim(), $options: "i" } },
                  { title: { $regex: search.trim(), $options: "i" } },
               ];
            }
            if (transportType?.trim() && transportType !== "all") {
               query.transportType = transportType;
            }

            const count = await ticketCollection.countDocuments(query);
            res.status(200).json({ count });
         } catch (error) {
            console.error("Error counting tickets:", error);
            res.status(500).json({ message: "Failed to count tickets." });
         }
      });

      // public: latest 6-8 approved tickets (Home page)
      app.get("/tickets/latest", async (req, res) => {
         try {
            const tickets = await ticketCollection
               .find({ verificationStatus: "approved", isHidden: { $ne: true } })
               .sort({ createdAt: -1 })
               .limit(8)
               .toArray();
            res.status(200).json(tickets);
         } catch (error) {
            console.error("Error fetching latest tickets:", error);
            res.status(500).json({ message: "Failed to fetch latest tickets." });
         }
      });

      // public: admin-advertised tickets, max 6 (Home page advertisement section)
      app.get("/tickets/advertised", async (req, res) => {
         try {
            const tickets = await ticketCollection
               .find({ isAdvertised: true, verificationStatus: "approved", isHidden: { $ne: true } })
               .limit(6)
               .toArray();
            res.status(200).json(tickets);
         } catch (error) {
            console.error("Error fetching advertised tickets:", error);
            res.status(500).json({ message: "Failed to fetch advertised tickets." });
         }
      });

      // vendor: tickets added by a specific vendor ("My Added Tickets")
      app.get("/tickets/vendor/:email", verifyToken, verifyVendor, async (req, res) => {
         try {
            const { email } = req.params;
            const tickets = await ticketCollection.find({ vendorEmail: email }).sort({ createdAt: -1 }).toArray();
            res.status(200).json(tickets);
         } catch (error) {
            console.error("Error fetching vendor tickets:", error);
            res.status(500).json({ message: "Failed to fetch your tickets." });
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