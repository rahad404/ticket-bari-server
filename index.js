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

      // admin: get ALL tickets (pending, rejected, approved, hidden) for manage-tickets page
      app.get("/tickets/admin", verifyToken, verifyAdmin, async (req, res) => {
         try {
            const tickets = await ticketCollection.find().sort({ createdAt: -1 }).toArray();
            res.status(200).json(tickets);
         } catch (error) {
            console.error("Error fetching all tickets for admin:", error);
            res.status(500).json({ message: "Failed to fetch tickets." });
         }
      });

      // protected: single ticket details (Ticket Details page)
      app.get("/tickets/:id", verifyToken, async (req, res) => {
         try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid Ticket ID" });

            const ticket = await ticketCollection.findOne({ _id: new ObjectId(id) });
            if (!ticket) return res.status(404).json({ message: "Ticket not found." });

            res.status(200).json(ticket);
         } catch (error) {
            console.error("Error fetching ticket:", error);
            res.status(500).json({ message: "Failed to fetch ticket details." });
         }
      });

      // admin: approve / reject a ticket
      app.patch("/tickets/verify/:id", verifyToken, verifyAdmin, async (req, res) => {
         try {
            const { id } = req.params;
            const { verificationStatus } = req.body;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid Ticket ID" });
            if (!["approved", "rejected"].includes(verificationStatus)) {
               return res.status(400).json({ message: "Invalid verification status." });
            }

            const result = await ticketCollection.updateOne(
               { _id: new ObjectId(id) },
               { $set: { verificationStatus } }
            );
            if (result.matchedCount === 0) return res.status(404).json({ message: "Ticket not found." });

            res.status(200).json({ success: true, message: `Ticket ${verificationStatus} successfully.` });
         } catch (error) {
            console.error("Error verifying ticket:", error);
            res.status(500).json({ message: "Failed to update verification status." });
         }
      });

      // admin: toggle advertise on/off (max 6 advertised tickets at a time)
      app.patch("/tickets/advertise/:id", verifyToken, verifyAdmin, async (req, res) => {
         try {
            const { id } = req.params;
            const { isAdvertised } = req.body;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid Ticket ID" });

            if (isAdvertised) {
               const currentCount = await ticketCollection.countDocuments({ isAdvertised: true });
               if (currentCount >= 6) {
                  return res.status(400).json({ message: "Cannot advertise more than 6 tickets at a time." });
               }
            }

            const result = await ticketCollection.updateOne(
               { _id: new ObjectId(id) },
               { $set: { isAdvertised: !!isAdvertised } }
            );
            if (result.matchedCount === 0) return res.status(404).json({ message: "Ticket not found." });

            res.status(200).json({
               success: true,
               message: `Ticket ${isAdvertised ? "advertised" : "unadvertised"} successfully.`,
            });
         } catch (error) {
            console.error("Error updating advertise status:", error);
            res.status(500).json({ message: "Failed to update advertise status." });
         }
      });

      // vendor: update own ticket (blocked if rejected)
      app.patch("/tickets/:id", verifyToken, verifyVendor, async (req, res) => {
         try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid Ticket ID" });

            const ticket = await ticketCollection.findOne({ _id: new ObjectId(id) });
            if (!ticket) return res.status(404).json({ message: "Ticket not found." });
            if (ticket.vendorEmail !== req.user.email) return res.status(403).json({ message: "forbidden access" });
            if (ticket.verificationStatus === "rejected") {
               return res.status(400).json({ message: "Rejected tickets cannot be updated." });
            }

            const updates = req.body;
            delete updates._id;
            delete updates.verificationStatus; // vendor cannot self-approve
            delete updates.isAdvertised; // vendor cannot self-advertise
            if (updates.price !== undefined) updates.price = Number(updates.price);
            if (updates.quantity !== undefined) updates.quantity = Number(updates.quantity);

            await ticketCollection.updateOne({ _id: new ObjectId(id) }, { $set: updates });
            res.status(200).json({ success: true, message: "Ticket updated successfully." });
         } catch (error) {
            console.error("Error updating ticket:", error);
            res.status(500).json({ message: "Failed to update ticket." });
         }
      });

      // vendor: delete own ticket (blocked if rejected)
      app.delete("/tickets/:id", verifyToken, verifyVendor, async (req, res) => {
         try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid Ticket ID" });

            const ticket = await ticketCollection.findOne({ _id: new ObjectId(id) });
            if (!ticket) return res.status(404).json({ message: "Ticket not found." });
            if (ticket.vendorEmail !== req.user.email) return res.status(403).json({ message: "forbidden access" });
            if (ticket.verificationStatus === "rejected") {
               return res.status(400).json({ message: "Rejected tickets cannot be deleted." });
            }

            await ticketCollection.deleteOne({ _id: new ObjectId(id) });
            res.status(200).json({ success: true, message: "Ticket deleted successfully." });
         } catch (error) {
            console.error("Error deleting ticket:", error);
            res.status(500).json({ message: "Failed to delete ticket." });
         }
      });

      // BOOKING ROUTES
      // ===================================================================

      // user books a ticket (status starts as "pending")
      app.post("/bookings", verifyToken, async (req, res) => {
         try {
            const { ticketId, bookingQuantity, userEmail, userName } = req.body;
            if (!ObjectId.isValid(ticketId)) return res.status(400).json({ message: "Invalid Ticket ID" });

            const ticket = await ticketCollection.findOne({ _id: new ObjectId(ticketId) });
            if (!ticket) return res.status(404).json({ message: "Ticket not found." });

            if (ticket.verificationStatus !== "approved" || ticket.isHidden) {
               return res.status(400).json({ message: "This ticket is not available for booking." });
            }

            if (Number(ticket.quantity) <= 0) {
               return res.status(400).json({ message: "This ticket is sold out." });
            }

            const qty = Number(bookingQuantity);
            if (!qty || qty <= 0) return res.status(400).json({ message: "Invalid booking quantity." });
            if (qty > Number(ticket.quantity)) {
               return res.status(400).json({ message: "Booking quantity exceeds available tickets." });
            }

            const departure = new Date(ticket.departureDateTime);
            if (departure < new Date()) {
               return res.status(400).json({ message: "Departure date and time has already passed." });
            }

            const newBooking = {
               ticketId: new ObjectId(ticketId),
               ticketTitle: ticket.title,
               ticketImage: ticket.image,
               from: ticket.from,
               to: ticket.to,
               transportType: ticket.transportType,
               departureDateTime: ticket.departureDateTime,
               unitPrice: Number(ticket.price),
               bookingQuantity: qty,
               totalPrice: Number(ticket.price) * qty,
               userEmail,
               userName,
               vendorEmail: ticket.vendorEmail,
               status: "pending",
               createdAt: new Date(),
            };

            const result = await bookingCollection.insertOne(newBooking);
            res.status(201).json({
               success: true,
               message: "Booking request submitted successfully.",
               bookingId: result.insertedId,
            });
         } catch (error) {
            console.error("Error creating booking:", error);
            res.status(500).json({ message: "Failed to create booking." });
         }
      });

      // user: own booked tickets ("My Booked Tickets")
      app.get("/bookings/user/:email", verifyToken, async (req, res) => {
         try {
            const { email } = req.params;
            const bookings = await bookingCollection.find({ userEmail: email }).sort({ createdAt: -1 }).toArray();
            res.status(200).json(bookings);
         } catch (error) {
            console.error("Error fetching user bookings:", error);
            res.status(500).json({ message: "Failed to fetch bookings." });
         }
      });

      // vendor: booking requests for their tickets ("Requested Bookings")
      app.get("/bookings/vendor/:email", verifyToken, verifyVendor, async (req, res) => {
         try {
            const { email } = req.params;
            const bookings = await bookingCollection.find({ vendorEmail: email }).sort({ createdAt: -1 }).toArray();
            res.status(200).json(bookings);
         } catch (error) {
            console.error("Error fetching vendor bookings:", error);
            res.status(500).json({ message: "Failed to fetch booking requests." });
         }
      });

      // single booking (used on the payment page to calculate amount)
      app.get("/bookings/:id", verifyToken, async (req, res) => {
         try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid Booking ID" });

            const booking = await bookingCollection.findOne({ _id: new ObjectId(id) });
            if (!booking) return res.status(404).json({ message: "Booking not found." });

            res.status(200).json(booking);
         } catch (error) {
            console.error("Error fetching booking:", error);
            res.status(500).json({ message: "Failed to fetch booking." });
         }
      });

      // vendor: accept a booking request
      app.patch("/bookings/accept/:id", verifyToken, verifyVendor, async (req, res) => {
         try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid Booking ID" });

            const result = await bookingCollection.updateOne(
               { _id: new ObjectId(id), vendorEmail: req.user.email },
               { $set: { status: "accepted" } }
            );
            if (result.matchedCount === 0) return res.status(404).json({ message: "Booking not found." });

            res.status(200).json({ success: true, message: "Booking accepted successfully." });
         } catch (error) {
            console.error("Error accepting booking:", error);
            res.status(500).json({ message: "Failed to accept booking." });
         }
      });

      // vendor: reject a booking request
      app.patch("/bookings/reject/:id", verifyToken, verifyVendor, async (req, res) => {
         try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid Booking ID" });

            const result = await bookingCollection.updateOne(
               { _id: new ObjectId(id), vendorEmail: req.user.email },
               { $set: { status: "rejected" } }
            );
            if (result.matchedCount === 0) return res.status(404).json({ message: "Booking not found." });

            res.status(200).json({ success: true, message: "Booking rejected successfully." });
         } catch (error) {
            console.error("Error rejecting booking:", error);
            res.status(500).json({ message: "Failed to reject booking." });
         }
      });

      // user: cancel a booking (optional feature - only allowed before vendor accepts)
      app.delete("/bookings/:id", verifyToken, async (req, res) => {
         try {
            const { id } = req.params;
            if (!ObjectId.isValid(id)) return res.status(400).json({ message: "Invalid Booking ID" });

            const booking = await bookingCollection.findOne({ _id: new ObjectId(id) });
            if (!booking) return res.status(404).json({ message: "Booking not found." });
            if (booking.status !== "pending") {
               return res.status(400).json({ message: "Only pending bookings can be cancelled." });
            }

            await bookingCollection.deleteOne({ _id: new ObjectId(id) });
            res.status(200).json({ success: true, message: "Booking cancelled successfully." });
         } catch (error) {
            console.error("Error cancelling booking:", error);
            res.status(500).json({ message: "Failed to cancel booking." });
         }
      });

      // PAYMENT ROUTES (Stripe)
      // ===================================================================

      // create a Stripe payment intent for an accepted booking
      // app.post("/create-payment-intent", verifyToken, async (req, res) => {
      //    try {
      //       const { bookingId } = req.body;
      //       if (!ObjectId.isValid(bookingId)) return res.status(400).json({ message: "Invalid Booking ID" });

      //       const booking = await bookingCollection.findOne({ _id: new ObjectId(bookingId) });
      //       if (!booking) return res.status(404).json({ message: "Booking not found." });
      //       if (booking.status !== "accepted") {
      //          return res.status(400).json({ message: "This booking is not approved for payment yet." });
      //       }

      //       const departure = new Date(booking.departureDateTime);
      //       if (departure < new Date()) {
      //          return res.status(400).json({ message: "Departure date and time has already passed." });
      //       }

      //       const amount = Math.round(Number(booking.totalPrice) * 100); // smallest currency unit

      //       const paymentIntent = await stripe.paymentIntents.create({
      //          amount,
      //          currency: "usd", // change as needed for your Stripe account
      //          payment_method_types: ["card"],
      //       });

      //       res.status(200).json({ clientSecret: paymentIntent.client_secret });
      //    } catch (error) {
      //       console.error("Error creating payment intent:", error);
      //       res.status(500).json({ message: "Failed to create payment intent." });
      //    }
      // });

      // save a successful payment, mark booking as paid, reduce ticket quantity
      // app.post("/payments", verifyToken, async (req, res) => {
      //    try {
      //       const { bookingId, transactionId, amount, email } = req.body;
      //       if (!ObjectId.isValid(bookingId)) return res.status(400).json({ message: "Invalid Booking ID" });

      //       const booking = await bookingCollection.findOne({ _id: new ObjectId(bookingId) });
      //       if (!booking) return res.status(404).json({ message: "Booking not found." });

      //       const paymentRecord = {
      //          transactionId,
      //          bookingId: new ObjectId(bookingId),
      //          ticketId: booking.ticketId,
      //          ticketTitle: booking.ticketTitle,
      //          amount: Number(amount),
      //          email,
      //          paymentDate: new Date(),
      //       };

      //       await paymentCollection.insertOne(paymentRecord);

      //       await bookingCollection.updateOne({ _id: new ObjectId(bookingId) }, { $set: { status: "paid" } });

      //       await ticketCollection.updateOne(
      //          { _id: booking.ticketId },
      //          { $inc: { quantity: -Number(booking.bookingQuantity) } }
      //       );

      //       res.status(201).json({ success: true, message: "Payment recorded successfully." });
      //    } catch (error) {
      //       console.error("Error saving payment:", error);
      //       res.status(500).json({ message: "Failed to save payment." });
      //    }
      // });

      // user: transaction history table
      // app.get("/payments/:email", verifyToken, async (req, res) => {
      //    try {
      //       const { email } = req.params;
      //       const payments = await paymentCollection.find({ email }).sort({ paymentDate: -1 }).toArray();
      //       res.status(200).json(payments);
      //    } catch (error) {
      //       console.error("Error fetching payments:", error);
      //       res.status(500).json({ message: "Failed to fetch transaction history." });
      //    }
      // });

      // VENDOR REVENUE OVERVIEW
      // ===================================================================

      app.get("/vendor-stats/:email", verifyToken, verifyVendor, async (req, res) => {
         try {
            const { email } = req.params;

            const totalTicketsAdded = await ticketCollection.countDocuments({ vendorEmail: email });

            const soldStats = await bookingCollection
               .aggregate([
                  { $match: { vendorEmail: email, status: "paid" } },
                  {
                     $group: {
                        _id: null,
                        totalTicketsSold: { $sum: "$bookingQuantity" },
                        totalRevenue: { $sum: "$totalPrice" },
                     },
                  },
               ])
               .toArray();

            const totalTicketsSold = soldStats[0]?.totalTicketsSold || 0;
            const totalRevenue = soldStats[0]?.totalRevenue || 0;

            res.status(200).json({ totalTicketsAdded, totalTicketsSold, totalRevenue });
         } catch (error) {
            console.error("Error fetching vendor stats:", error);
            res.status(500).json({ message: "Failed to fetch vendor stats." });
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