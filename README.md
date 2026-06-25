# TicketBari – Ticket Booking System (Server API)

### **Programming Hero | Batch-13 | Assignment-10 | MERN Stack Development Project | CAT-10**

* **Project Name:** TicketBari – Ticket Booking System (Backend)  
* **Server GitHub Repository:** [https://github.com/rahad404/ticket-bari-server](#)
* **Client GitHub Repository:** [https://github.com/rahad404/ticket-bari-client](#)
* **Client Live Site:** [https://ticket-bari-client-tan.vercel.app/](#)  
* **Server Live Site:** [https://ticket-bari-server-seven.vercel.app/](#)  

---

## Project Description

The **TicketBari Server** is a secure, high-performance RESTful API built with **Express.js** and **Node.js**. It serves as the backend engine for the TicketBari ticket booking platform, managing user roles, ticket inventory, booking workflows, and vendor fraud detection. The API supports role-based access control (Admin, Vendor, User), advanced ticket search with filtering and pagination, and a full approval lifecycle for tickets. Authentication is handled via **BetterAuth JWKS** using the `jose` library.

---

## Key Features

1. **Role‑Based Access Control (RBAC):** Three distinct roles – `admin`, `vendor`, `user` – enforced by JWT verification and dedicated middleware.
2. **Ticket Verification Workflow:** Vendors submit tickets for admin review; admins can approve or reject. Approved tickets become publicly visible.
3. **Smart Search & Filtering:** Public ticket listing supports search across multiple fields (`from`, `to`, `title`), filtering by `transportType`, dynamic sorting (price asc/desc), and pagination.
4. **Fraud Protection for Vendors:** Admins can mark a vendor as fraudulent, automatically hiding all their tickets from public view and blocking future submissions.
5. **Advertisement Management:** Admins can feature up to 6 approved tickets on the homepage via a toggle.
6. **Booking Lifecycle:** Users create pending bookings; vendors can accept or reject them. Only accepted bookings proceed to payment (Stripe integration designed but currently disabled). Cancelations are allowed only before vendor action.
7. **Atomic Updates with Native MongoDB:** Operations like booking creation validate ticket availability and departure time in one atomic flow.
8. **Vendor Statistics Dashboard:** Aggregated stats (total tickets added, tickets sold, revenue) available per vendor.

---

## Tech Stack

* **Runtime & Framework:** Node.js & Express.js  
* **Database Driver:** MongoDB Native Driver (`mongodb` v7.2)  
* **Authentication:** JWT verification via **jose‑cjs** (BetterAuth JWKS)  
* **Environment Configuration:** `dotenv`  
* **Cross‑Origin Support:** `cors`  
* **Deployment:** Ready for Vercel or any Node.js hosting  

---

## API Endpoints

All endpoints are relative to the base URL:  
**`http://localhost:5000`** (development) or your production domain.

> **Authentication:** Most endpoints require a valid JWT token sent in the `Authorization` header as `Bearer <token>`. The token payload must contain the user’s email (e.g., `payload.email`). Role‑specific endpoints are noted with `Admin` / `Vendor` / `User`.

---

### 1. User Routes

| Method | Endpoint                | Auth Required        | Description |
|--------|-------------------------|----------------------|-------------|
| `GET`  | `/users`                | `Admin`              | Retrieve all users sorted by newest first. |
| `GET`  | `/users/role/:email`    | `User` (own email)   | Fetch the role (`user`/`vendor`/`admin`) and fraud flag for a given email. Useful for client‑side route protection. |
| `GET`  | `/users/:email`         | `User` (own email)   | Get the full profile of a user by email. |
| `PATCH`| `/users/admin/:id`      | `Admin`              | Promote a user to `admin` using their MongoDB `_id`. |
| `PATCH`| `/users/vendor/:id`     | `Admin`              | Promote a user to `vendor`. |
| `PATCH`| `/users/fraud/:id`      | `Admin`              | Mark a **vendor** as fraudulent. Automatically hides all their tickets. |
| `PATCH`| `/users/:id`            | `User` (own ID)      | Update own profile fields (`name`, `image`). Only the authenticated user can modify their own data. |

---

### 2. Ticket Routes

| Method   | Endpoint                    | Auth Required | Description |
|----------|-----------------------------|---------------|-------------|
| `POST`   | `/tickets`                  | `Vendor`      | Submit a new ticket. The ticket’s `verificationStatus` is set to `pending`, `isAdvertised` to `false`, and `isHidden` to `false`. |
| `GET`    | `/tickets`                  | Public        | Retrieve **approved, non‑hidden** tickets. Supports query params: `search`, `from`, `to`, `transportType`, `sort` ( `price_asc` / `price_desc` ), `page`, `limit`. |
| `GET`    | `/tickets-count`            | Public        | Return the total count of tickets matching the same filters as `/tickets` (without pagination). Useful for pagination UI. |
| `GET`    | `/tickets/latest`           | Public        | Get the **latest 8** approved tickets for the homepage. |
| `GET`    | `/tickets/advertised`       | Public        | Get up to **6** tickets marked as advertised by admin. |
| `GET`    | `/tickets/vendor/:email`    | `Vendor`      | Retrieve all tickets added by a specific vendor. |
| `GET`    | `/tickets/:id`              | `User`        | Fetch full details of a single ticket by its `_id`. |
| `PATCH`  | `/tickets/verify/:id`       | `Admin`       | Approve or reject a ticket. Request body: `{ "verificationStatus": "approved" | "rejected" }` |
| `PATCH`  | `/tickets/advertise/:id`    | `Admin`       | Toggle the `isAdvertised` flag. Admin can advertise a maximum of 6 tickets at a time. |
| `PATCH`  | `/tickets/:id`              | `Vendor`      | Update a vendor’s own ticket. **Not allowed** if the ticket has been rejected. Cannot modify `verificationStatus` or `isAdvertised`. |
| `DELETE` | `/tickets/:id`              | `Vendor`      | Delete a vendor’s own ticket. **Not allowed** if the ticket has been rejected. |

---

### 3. Booking Routes

| Method   | Endpoint                     | Auth Required | Description |
|----------|------------------------------|---------------|-------------|
| `POST`   | `/bookings`                  | `User`        | Create a booking request. Validates ticket availability and departure time. Booking status starts as `pending`. Request body: `{ ticketId, bookingQuantity, userEmail, userName }` |
| `GET`    | `/bookings/user/:email`      | `User`        | Fetch all bookings made by a specific user (by email). |
| `GET`    | `/bookings/vendor/:email`    | `Vendor`      | Fetch all booking requests for tickets belonging to a vendor. |
| `GET`    | `/bookings/:id`              | `User`        | Retrieve a single booking by its `_id`. Used on the payment page to display the amount. |
| `PATCH`  | `/bookings/accept/:id`       | `Vendor`      | Accept a booking request. Sets status to `accepted`. |
| `PATCH`  | `/bookings/reject/:id`       | `Vendor`      | Reject a booking request. Sets status to `rejected`. |
| `DELETE` | `/bookings/:id`              | `User`        | Cancel a **pending** booking. Only allowed before the vendor accepts/rejects. |

---

### 4. Vendor Statistics

| Method | Endpoint                  | Auth Required | Description |
|--------|---------------------------|---------------|-------------|
| `GET`  | `/vendor-stats/:email`    | `Vendor`      | Returns aggregated data: `totalTicketsAdded`, `totalTicketsSold` (from paid bookings), and `totalRevenue`. |

---

### 5. Payment Routes (Designed – Stripe Integration)

> **These endpoints are currently commented out in the code** and are included here for reference. They illustrate the planned payment flow with Stripe. Uncomment and configure Stripe keys to enable them.

| Method | Endpoint                   | Auth Required | Description |
|--------|----------------------------|---------------|-------------|
| `POST` | `/create-payment-intent`   | `User`        | Creates a Stripe PaymentIntent for an accepted booking. Returns a `clientSecret`. |
| `POST` | `/payments`                | `User`        | Saves a successful payment, marks the booking as `paid`, and decrements the ticket’s available quantity. |
| `GET`  | `/payments/:email`         | `User`        | Retrieves transaction history for a user. |

---

## Getting Started (Local Setup)

### 1. Clone the repository
```bash
git clone https://github.com/your-username/ticket-bari-server.git
cd ticketbari-server