import {
  BadRequestException,
  ForbiddenException,
  Injectable,
  InternalServerErrorException,
  UnauthorizedException,
} from '@nestjs/common';
import { JwtService } from '@nestjs/jwt';
import { ConfigService } from '@nestjs/config';
import * as bcrypt from 'bcrypt';
import { PrismaService } from '../prisma/prisma.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { AuthTokens } from './types/auth-tokens.type';

const ACCESS_TOKEN_TTL = '15m';
const REFRESH_TOKEN_TTL = '7d';
const SALT_ROUNDS = 12;

@Injectable()
export class AuthService {
  constructor(
    private readonly prisma: PrismaService,
    private readonly jwtService: JwtService,
    private readonly configService: ConfigService,
  ) {}

  async register(dto: RegisterDto): Promise<AuthTokens> {
    const email = this.normalizeEmail(dto.email);

    if (dto.role && dto.role !== 'TEAM_MEMBER') {
      throw new ForbiddenException('Role assignment is not allowed.');
    }

    const existingUser = await this.prisma.user.findUnique({
      where: { email },
      select: { id: true },
    });

    if (existingUser) {
      throw new BadRequestException('Email already registered.');
    }

    const passwordHash = await bcrypt.hash(dto.password, SALT_ROUNDS);

    const user = await this.prisma.user.create({
      data: {
        email,
        passwordHash,
        role: 'TEAM_MEMBER',
        status: 'ACTIVE',
      },
      select: { id: true, email: true, role: true },
    });

    const tokens = await this.generateTokens(user.id, user.email, user.role);
    await this.storeRefreshTokenHash(user.id, tokens.refreshToken);

    return tokens;
  }

  async login(dto: LoginDto): Promise<AuthTokens> {
    const email = this.normalizeEmail(dto.email);

    const user = await this.prisma.user.findUnique({
      where: { email },
      select: {
        id: true,
        email: true,
        passwordHash: true,
        role: true,
        status: true,
      },
    });

    if (!user || user.status !== 'ACTIVE') {
      throw new UnauthorizedException('Invalid credentials.');
    }

    const passwordMatches = await bcrypt.compare(dto.password, user.passwordHash);
    if (!passwordMatches) {
      throw new UnauthorizedException('Invalid credentials.');
    }

    const tokens = await this.generateTokens(user.id, user.email, user.role);
    await this.storeRefreshTokenHash(user.id, tokens.refreshToken);

    return tokens;
  }

  async refreshTokens(userId: string, refreshToken: string): Promise<AuthTokens> {
    const user = await this.prisma.user.findUnique({
      where: { id: userId },
      select: {
        id: true,
        email: true,
        role: true,
        refreshTokenHash: true,
        status: true,
      },
    });

    if (!user || user.status !== 'ACTIVE' || !user.refreshTokenHash) {
      throw new ForbiddenException('Access denied.');
    }

    const refreshTokenValid = await bcrypt.compare(
      refreshToken,
      user.refreshTokenHash,
    );

    if (!refreshTokenValid) {
      throw new ForbiddenException('Access denied.');
    }

    const tokens = await this.generateTokens(user.id, user.email, user.role);
    await this.storeRefreshTokenHash(user.id, tokens.refreshToken);

    return tokens;
  }

  async logout(userId: string): Promise<void> {
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshTokenHash: null },
    });
  }

  async verifyRefreshToken(refreshToken: string): Promise<{ sub: string }> {
    try {
      return await this.jwtService.verifyAsync(refreshToken, {
        secret: this.getRequiredConfig('JWT_REFRESH_SECRET'),
      });
    } catch {
      throw new UnauthorizedException('Refresh token expired or invalid.');
    }
  }

  private async generateTokens(
    userId: string,
    email: string,
    role: string,
  ): Promise<AuthTokens> {
    const payload = { sub: userId, email, role };
    const [accessToken, refreshToken] = await Promise.all([
      this.jwtService.signAsync(payload, {
        secret: this.getRequiredConfig('JWT_ACCESS_SECRET'),
        expiresIn: ACCESS_TOKEN_TTL,
      }),
      this.jwtService.signAsync(payload, {
        secret: this.getRequiredConfig('JWT_REFRESH_SECRET'),
        expiresIn: REFRESH_TOKEN_TTL,
      }),
    ]);

    return { accessToken, refreshToken };
  }

  private async storeRefreshTokenHash(userId: string, refreshToken: string) {
    const refreshTokenHash = await bcrypt.hash(refreshToken, SALT_ROUNDS);
    await this.prisma.user.update({
      where: { id: userId },
      data: { refreshTokenHash },
    });
  }

  private normalizeEmail(email: string): string {
    return email.trim().toLowerCase();
  }

  private getRequiredConfig(key: string): string {
    const value = this.configService.get<string>(key);
    if (!value) {
      throw new InternalServerErrorException(`Missing ${key} configuration.`);
    }
    return value;
  }
}
