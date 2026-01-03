// Device types and interfaces
export interface Device {
  id: string;
  name: string;
  type: 'sensor' | 'camera' | 'beacon' | 'emergency_button';
  status: 'online' | 'offline' | 'warning';
  location: string;
  lastSeen: Date;
  batteryLevel: number | undefined;
  userId: string;
  metadata: {
    model: string | undefined;
    firmwareVersion: string | undefined;
    installationDate: Date | undefined;
    lastMaintenanceDate: Date | undefined;
  } | undefined;
}

// Alert types and interfaces
export type AlertType = 'emergency' | 'warning' | 'info' | 'maintenance';
export type AlertSeverity = 'critical' | 'high' | 'medium' | 'low';

export interface Alert {
  id: string;
  type: AlertType;
  severity: AlertSeverity;
  title: string;
  message: string;
  timestamp: Date;
  deviceId?: string;
  userId: string;
  isRead: boolean;
  isResolved: boolean;
  resolvedAt?: Date;
  resolvedBy?: string;
  metadata?: {
    location?: string;
    deviceName?: string;
    triggerValue?: number;
    threshold?: number;
  };
}

// User authentication and profile interfaces
export interface User {
  id: string;
  email: string;
  password: string; // Hashed
  firstName: string;
  lastName: string;
  phone: string | undefined;
  role: 'admin' | 'user' | 'caregiver';
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
  lastLoginAt: Date | undefined;
  preferences: {
    notifications: {
      email: boolean;
      sms: boolean;
      push: boolean;
    };
    alertThresholds: {
      batteryWarning: number;
      inactivityTimeout: number; // in minutes
    };
  } | undefined;
}

export interface CreateUserRequest {
  email: string;
  password: string;
  firstName: string;
  lastName: string;
  phone?: string;
  role?: 'user' | 'caregiver';
}

export interface LoginRequest {
  email: string;
  password: string;
}

export interface AuthResponse {
  token: string;
  user: Omit<User, 'password'>;
  expiresIn: number;
}

// Device status update interface
export interface DeviceStatusUpdate {
  status: Device['status'];
  batteryLevel?: number;
  metadata?: Device['metadata'];
}

// API Response interfaces
export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  message?: string;
  error?: string;
  timestamp: Date;
}

export interface PaginatedResponse<T> extends ApiResponse<T[]> {
  pagination: {
    page: number;
    limit: number;
    total: number;
    totalPages: number;
  };
}

// JWT Payload interface
export interface JwtPayload {
  userId: string;
  email: string;
  role: User['role'];
  iat: number;
  exp: number;
}

// Express Request with authenticated user
import { Request } from 'express';

export interface AuthenticatedRequest extends Request {
  user?: JwtPayload;
}

// Environment variables interface
export interface EnvConfig {
  PORT: number;
  NODE_ENV: 'development' | 'production' | 'test';
  JWT_SECRET: string;
  JWT_EXPIRES_IN: string;
  BCRYPT_ROUNDS: number;
  CORS_ORIGIN: string;
  DATABASE_URL?: string;
}

// Error types
export interface ApiError extends Error {
  statusCode: number;
  code: string | undefined;
}

// Health check response
export interface HealthCheckResponse {
  status: 'healthy' | 'unhealthy';
  uptime: number;
  timestamp: Date;
  version: string;
  environment: string;
  database?: {
    connected: boolean;
    responseTime?: number;
  };
}

// Device creation request
export interface CreateDeviceRequest {
  name: string;
  type: Device['type'];
  location: string;
  metadata: Device['metadata'];
}