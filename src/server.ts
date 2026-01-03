import express, { Request, Response } from 'express';
import cors from 'cors';
import dotenv from 'dotenv';
import jwt from 'jsonwebtoken';
import bcrypt from 'bcrypt';
import { v4 as uuidv4 } from 'uuid';

// Load environment variables
dotenv.config();

// Import types and middleware
import {
  ApiResponse,
  Device,
  Alert,
  User,
  CreateUserRequest,
  LoginRequest,
  AuthResponse,
  DeviceStatusUpdate,
  HealthCheckResponse,
  AuthenticatedRequest,
  CreateDeviceRequest,
} from './types';
import { errorHandler, notFoundHandler, asyncHandler, AppError } from './middleware/errorHandler';
import { authenticateToken, requireRole, optionalAuth } from './middleware/auth';

// Initialize Express app
const app = express();
const PORT = process.env.PORT || 3001;

// Middleware
app.use(cors({
  origin: process.env.CORS_ORIGIN || 'http://localhost:3000',
  credentials: true,
}));
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true }));

// Request logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// Mock data stores (In production, these would be replaced with database calls)
const users: User[] = [];
const devices: Device[] = [
  {
    id: '1',
    name: 'Living Room Motion Sensor',
    type: 'sensor',
    status: 'online',
    location: 'Living Room',
    lastSeen: new Date(),
    batteryLevel: 85,
    userId: 'user1',
    metadata: {
      model: 'MS-100',
      firmwareVersion: '1.2.3',
      installationDate: new Date('2023-01-15'),
      lastMaintenanceDate: undefined,
    },
  },
  {
    id: '2',
    name: 'Kitchen Safety Camera',
    type: 'camera',
    status: 'online',
    location: 'Kitchen',
    lastSeen: new Date(),
    batteryLevel: undefined,
    userId: 'user1',
    metadata: {
      model: 'CAM-200',
      firmwareVersion: '2.1.0',
      installationDate: new Date('2023-02-01'),
      lastMaintenanceDate: undefined,
    },
  },
  {
    id: '3',
    name: 'Bedroom Fall Detector',
    type: 'sensor',
    status: 'warning',
    location: 'Bedroom',
    lastSeen: new Date(Date.now() - 15 * 60 * 1000), // 15 minutes ago
    batteryLevel: 25,
    userId: 'user1',
    metadata: {
      model: 'FD-150',
      firmwareVersion: '1.0.5',
      installationDate: new Date('2023-01-20'),
      lastMaintenanceDate: undefined,
    },
  },
  {
    id: '4',
    name: 'Emergency Button - Bathroom',
    type: 'emergency_button',
    status: 'online',
    location: 'Bathroom',
    lastSeen: new Date(Date.now() - 5 * 60 * 1000), // 5 minutes ago
    batteryLevel: 95,
    userId: 'user1',
    metadata: {
      model: 'EB-50',
      firmwareVersion: '1.1.0',
      installationDate: new Date('2023-01-10'),
      lastMaintenanceDate: undefined,
    },
  },
];

const alerts: Alert[] = [
  {
    id: '1',
    type: 'warning',
    severity: 'high',
    title: 'Low Battery Warning',
    message: 'Bedroom Fall Detector battery is running low (25%)',
    timestamp: new Date(Date.now() - 30 * 60 * 1000), // 30 minutes ago
    deviceId: '3',
    userId: 'user1',
    isRead: false,
    isResolved: false,
    metadata: {
      location: 'Bedroom',
      deviceName: 'Bedroom Fall Detector',
      triggerValue: 25,
      threshold: 30,
    },
  },
  {
    id: '2',
    type: 'info',
    severity: 'low',
    title: 'Device Check-in',
    message: 'All devices completed scheduled health check',
    timestamp: new Date(Date.now() - 2 * 60 * 60 * 1000), // 2 hours ago
    userId: 'user1',
    isRead: true,
    isResolved: true,
    resolvedAt: new Date(Date.now() - 2 * 60 * 60 * 1000),
  },
];

// Utility functions
const generateToken = (user: Omit<User, 'password'>): string => {
  const jwtSecret = process.env.JWT_SECRET || 'default-secret-key';
  const expiresIn = process.env.JWT_EXPIRES_IN || '7d';

  const payload = {
    userId: user.id,
    email: user.email,
    role: user.role,
  };

  return jwt.sign(payload, jwtSecret, { expiresIn } as jwt.SignOptions);
};

const hashPassword = async (password: string): Promise<string> => {
  const saltRounds = parseInt(process.env.BCRYPT_ROUNDS || '10');
  return await bcrypt.hash(password, saltRounds);
};

const comparePassword = async (password: string, hash: string): Promise<boolean> => {
  return await bcrypt.compare(password, hash);
};

// Health check endpoint
app.get('/health', (req: Request, res: Response) => {
  const response: HealthCheckResponse = {
    status: 'healthy',
    uptime: process.uptime(),
    timestamp: new Date(),
    version: process.env.npm_package_version || '1.0.0',
    environment: process.env.NODE_ENV || 'development',
    database: {
      connected: true, // In production, check actual database connection
      responseTime: Math.floor(Math.random() * 10) + 1, // Mock response time
    },
  };

  res.json(response);
});

// Authentication endpoints
app.post('/api/auth/register', asyncHandler(async (req: Request, res: Response) => {
  const { email, password, firstName, lastName, phone, role = 'user' }: CreateUserRequest = req.body;

  // Validation
  if (!email || !password || !firstName || !lastName) {
    throw new AppError('Missing required fields', 400, 'MISSING_FIELDS');
  }

  if (password.length < 6) {
    throw new AppError('Password must be at least 6 characters', 400, 'WEAK_PASSWORD');
  }

  // Check if user already exists
  const existingUser = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (existingUser) {
    throw new AppError('User already exists', 409, 'USER_EXISTS');
  }

  // Hash password and create user
  const hashedPassword = await hashPassword(password);
  const newUser: User = {
    id: uuidv4(),
    email: email.toLowerCase(),
    password: hashedPassword,
    firstName,
    lastName,
    phone: phone || undefined,
    role: role as User['role'],
    isActive: true,
    createdAt: new Date(),
    updatedAt: new Date(),
    lastLoginAt: undefined,
    preferences: {
      notifications: {
        email: true,
        sms: Boolean(phone),
        push: true,
      },
      alertThresholds: {
        batteryWarning: 30,
        inactivityTimeout: 60,
      },
    },
  };

  users.push(newUser);

  // Generate token
  const { password: _, ...userWithoutPassword } = newUser;
  const token = generateToken(userWithoutPassword);

  const response: AuthResponse = {
    token,
    user: userWithoutPassword,
    expiresIn: 7 * 24 * 60 * 60, // 7 days in seconds
  };

  const apiResponse: ApiResponse<AuthResponse> = {
    success: true,
    data: response,
    message: 'User registered successfully',
    timestamp: new Date(),
  };

  res.status(201).json(apiResponse);
}));

app.post('/api/auth/login', asyncHandler(async (req: Request, res: Response) => {
  const { email, password }: LoginRequest = req.body;

  if (!email || !password) {
    throw new AppError('Email and password are required', 400, 'MISSING_CREDENTIALS');
  }

  // Find user
  const user = users.find(u => u.email.toLowerCase() === email.toLowerCase());
  if (!user) {
    throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
  }

  if (!user.isActive) {
    throw new AppError('Account is disabled', 403, 'ACCOUNT_DISABLED');
  }

  // Check password
  const isPasswordValid = await comparePassword(password, user.password);
  if (!isPasswordValid) {
    throw new AppError('Invalid credentials', 401, 'INVALID_CREDENTIALS');
  }

  // Update last login
  user.lastLoginAt = new Date();
  user.updatedAt = new Date();

  // Generate token
  const { password: _, ...userWithoutPassword } = user;
  const token = generateToken(userWithoutPassword);

  const response: AuthResponse = {
    token,
    user: userWithoutPassword,
    expiresIn: 7 * 24 * 60 * 60, // 7 days in seconds
  };

  const apiResponse: ApiResponse<AuthResponse> = {
    success: true,
    data: response,
    message: 'Login successful',
    timestamp: new Date(),
  };

  res.json(apiResponse);
}));

// Device endpoints
app.get('/api/devices', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const userId = req.user?.userId;
  const userDevices = devices.filter(device => device.userId === userId);

  const apiResponse: ApiResponse<Device[]> = {
    success: true,
    data: userDevices,
    message: 'Devices retrieved successfully',
    timestamp: new Date(),
  };

  res.json(apiResponse);
}));

app.post('/api/devices', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const userId = req.user?.userId;
  const { name, type, location, metadata }: CreateDeviceRequest = req.body;

  if (!name || !type || !location) {
    throw new AppError('Missing required fields', 400, 'MISSING_FIELDS');
  }

  const newDevice: Device = {
    id: uuidv4(),
    name,
    type,
    location,
    status: 'online',
    lastSeen: new Date(),
    userId: userId!,
    batteryLevel: 100,
    metadata: metadata || undefined,
  };

  devices.push(newDevice);

  const apiResponse: ApiResponse<Device> = {
    success: true,
    data: newDevice,
    message: 'Device created successfully',
    timestamp: new Date(),
  };

  res.status(201).json(apiResponse);
}));

app.post('/api/devices/:id/status', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;
  const userId = req.user?.userId;
  const { status, batteryLevel, metadata }: DeviceStatusUpdate = req.body;

  const device = devices.find(d => d.id === id && d.userId === userId);
  if (!device) {
    throw new AppError('Device not found', 404, 'DEVICE_NOT_FOUND');
  }

  // Update device
  device.status = status;
  device.lastSeen = new Date();
  if (batteryLevel !== undefined) {
    device.batteryLevel = batteryLevel;
  }
  if (metadata) {
    device.metadata = { ...device.metadata, ...metadata };
  }

  // Create alert for low battery
  if (batteryLevel && batteryLevel < 30) {
    const alert: Alert = {
      id: uuidv4(),
      type: 'warning',
      severity: 'high',
      title: 'Low Battery Warning',
      message: `${device.name} battery is running low (${batteryLevel}%)`,
      timestamp: new Date(),
      deviceId: device.id,
      userId: userId!,
      isRead: false,
      isResolved: false,
      metadata: {
        location: device.location,
        deviceName: device.name,
        triggerValue: batteryLevel,
        threshold: 30,
      },
    };
    alerts.push(alert);
  }

  const apiResponse: ApiResponse<Device> = {
    success: true,
    data: device,
    message: 'Device status updated successfully',
    timestamp: new Date(),
  };

  res.json(apiResponse);
}));

// Alert endpoints
app.get('/api/alerts', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const userId = req.user?.userId;
  const { unread, limit = '50' } = req.query;

  let userAlerts = alerts.filter(alert => alert.userId === userId);

  // Filter by unread status if requested
  if (unread === 'true') {
    userAlerts = userAlerts.filter(alert => !alert.isRead);
  }

  // Sort by timestamp (newest first)
  userAlerts.sort((a, b) => b.timestamp.getTime() - a.timestamp.getTime());

  // Apply limit
  const limitNum = parseInt(limit as string);
  if (limitNum > 0) {
    userAlerts = userAlerts.slice(0, limitNum);
  }

  const apiResponse: ApiResponse<Alert[]> = {
    success: true,
    data: userAlerts,
    message: 'Alerts retrieved successfully',
    timestamp: new Date(),
  };

  res.json(apiResponse);
}));

app.patch('/api/alerts/:id/read', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const { id } = req.params;
  const userId = req.user?.userId;

  const alert = alerts.find(a => a.id === id && a.userId === userId);
  if (!alert) {
    throw new AppError('Alert not found', 404, 'ALERT_NOT_FOUND');
  }

  alert.isRead = true;

  const apiResponse: ApiResponse<Alert> = {
    success: true,
    data: alert,
    message: 'Alert marked as read',
    timestamp: new Date(),
  };

  res.json(apiResponse);
}));

// User profile endpoint
app.get('/api/user/profile', authenticateToken, asyncHandler(async (req: AuthenticatedRequest, res: Response) => {
  const userId = req.user?.userId;
  const user = users.find(u => u.id === userId);

  if (!user) {
    throw new AppError('User not found', 404, 'USER_NOT_FOUND');
  }

  const { password, ...userWithoutPassword } = user;

  const apiResponse: ApiResponse<Omit<User, 'password'>> = {
    success: true,
    data: userWithoutPassword,
    message: 'User profile retrieved successfully',
    timestamp: new Date(),
  };

  res.json(apiResponse);
}));

// Error handling middleware
app.use(notFoundHandler);
app.use(errorHandler);

// Start server
app.listen(PORT, () => {
  console.log(`🚀 Aging Safe Backend Server running on port ${PORT}`);
  console.log(`📋 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🌐 CORS origin: ${process.env.CORS_ORIGIN || 'http://localhost:3000'}`);
  console.log(`⚡ Health check available at: http://localhost:${PORT}/health`);
});

export default app;