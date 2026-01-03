# Aging Safe Backend API

A TypeScript Express.js backend API for the Aging Safe smart home monitoring system.

## 🚀 Features

- **TypeScript**: Full type safety throughout the application
- **Express.js**: Fast and minimal web framework
- **Authentication**: JWT-based user authentication with bcrypt password hashing
- **Security**: CORS protection, input validation, and secure error handling
- **Device Management**: CRUD operations for IoT devices
- **Alert System**: Real-time alert management and notifications
- **Health Monitoring**: Health check endpoints for system monitoring

## 📁 Project Structure

```
src/
├── types/
│   └── index.ts              # TypeScript interfaces and types
├── middleware/
│   ├── auth.ts              # JWT authentication middleware
│   └── errorHandler.ts      # Error handling and logging
├── routes/                  # API route handlers (future expansion)
├── controllers/             # Business logic controllers (future expansion)
└── server.ts               # Main Express server configuration
```

## 🔧 Installation

1. Install dependencies:
```bash
npm install
```

2. Set up environment variables:
```bash
cp .env.example .env
# Edit .env with your configuration
```

3. Start development server:
```bash
npm run dev
```

4. Build for production:
```bash
npm run build
npm start
```

## 📡 API Endpoints

### Authentication
- `POST /api/auth/register` - Register new user
- `POST /api/auth/login` - User login

### Devices
- `GET /api/devices` - List user's devices
- `POST /api/devices` - Create new device
- `POST /api/devices/:id/status` - Update device status

### Alerts
- `GET /api/alerts` - Get user alerts
- `PATCH /api/alerts/:id/read` - Mark alert as read

### Health Check
- `GET /health` - System health status

### User Profile
- `GET /api/user/profile` - Get user profile

## 🔐 Authentication

The API uses JWT (JSON Web Tokens) for authentication. Include the token in requests:

```bash
Authorization: Bearer <your-jwt-token>
```

## 📝 Request/Response Examples

### Register User
```bash
POST /api/auth/register
Content-Type: application/json

{
  "email": "user@example.com",
  "password": "securePassword123",
  "firstName": "John",
  "lastName": "Doe",
  "phone": "+1234567890"
}
```

### Get Devices
```bash
GET /api/devices
Authorization: Bearer <token>

Response:
{
  "success": true,
  "data": [
    {
      "id": "1",
      "name": "Living Room Motion Sensor",
      "type": "sensor",
      "status": "online",
      "location": "Living Room",
      "batteryLevel": 85,
      "lastSeen": "2024-01-02T20:00:00Z"
    }
  ]
}
```

### Update Device Status
```bash
POST /api/devices/1/status
Authorization: Bearer <token>
Content-Type: application/json

{
  "status": "warning",
  "batteryLevel": 15
}
```

## 🛠️ Configuration

Environment variables in `.env`:

- `PORT` - Server port (default: 3001)
- `NODE_ENV` - Environment (development/production)
- `JWT_SECRET` - Secret key for JWT tokens
- `JWT_EXPIRES_IN` - Token expiration time
- `CORS_ORIGIN` - Allowed CORS origin
- `BCRYPT_ROUNDS` - Password hashing rounds

## 🏗️ Architecture

### Type Safety
The application uses comprehensive TypeScript interfaces for:
- Device models and status updates
- User authentication and profiles
- API request/response types
- Alert system types
- Error handling types

### Security Features
- Password hashing with bcrypt
- JWT token authentication
- CORS protection
- Input validation
- Secure error handling
- Request logging

### Middleware Stack
1. CORS configuration
2. JSON body parsing
3. Request logging
4. Authentication validation
5. Error handling

## 🔄 Development

### Available Scripts
- `npm run dev` - Start development server with hot reload
- `npm run build` - Compile TypeScript to JavaScript
- `npm run start` - Start production server
- `npm run clean` - Remove build artifacts
- `npm run type-check` - Type check without compilation

### Mock Data
The application includes mock data for development:
- Sample IoT devices with different types and statuses
- Mock alerts and notifications
- Test user accounts

### Future Enhancements
- Database integration (PostgreSQL/MongoDB)
- WebSocket support for real-time updates
- SMS/Email notification services
- Device firmware update management
- Advanced analytics and reporting
- Multi-tenancy support
- Rate limiting and API throttling

## 📊 Health Monitoring

Health check endpoint provides system status:
```bash
GET /health

Response:
{
  "status": "healthy",
  "uptime": 3600,
  "timestamp": "2024-01-02T20:00:00Z",
  "version": "1.0.0",
  "environment": "development"
}
```

## 🚨 Error Handling

The API provides consistent error responses:
```json
{
  "success": false,
  "error": "INVALID_CREDENTIALS: Invalid email or password",
  "timestamp": "2024-01-02T20:00:00Z"
}
```

Common error codes:
- `MISSING_FIELDS` - Required fields missing
- `INVALID_CREDENTIALS` - Authentication failed
- `USER_EXISTS` - Email already registered
- `DEVICE_NOT_FOUND` - Device not found
- `INSUFFICIENT_PERMISSIONS` - Access denied

## 📄 License

MIT License