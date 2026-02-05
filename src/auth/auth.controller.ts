import {
  Body,
  Controller,
  Get,
  HttpCode,
  HttpStatus,
  Post,
  Req,
  UseGuards,
} from '@nestjs/common';
import { Request } from 'express';
import { AuthService } from './auth.service';
import { RegisterDto } from './dto/register.dto';
import { LoginDto } from './dto/login.dto';
import { RefreshTokenDto } from './dto/refresh-token.dto';
import { JwtAuthGuard } from './guards/jwt-auth.guard';
import { Roles } from './decorators/roles.decorator';
import { RolesGuard } from './guards/roles.guard';

@Controller('auth')
export class AuthController {
  constructor(private readonly authService: AuthService) {}

  @Post('register')
  @HttpCode(HttpStatus.CREATED)
  register(@Body() dto: RegisterDto) {
    return this.authService.register(dto);
  }

  @Post('login')
  @HttpCode(HttpStatus.OK)
  login(@Body() dto: LoginDto) {
    return this.authService.login(dto);
  }

  @Post('refresh')
  @HttpCode(HttpStatus.OK)
  async refresh(@Body() dto: RefreshTokenDto) {
    const payload = await this.authService.verifyRefreshToken(dto.refreshToken);
    return this.authService.refreshTokens(payload.sub, dto.refreshToken);
  }

  @Post('logout')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.NO_CONTENT)
  async logout(@Req() req: Request) {
    await this.authService.logout(req.user['id']);
  }

  @Get('me')
  @UseGuards(JwtAuthGuard)
  @HttpCode(HttpStatus.OK)
  getProfile(@Req() req: Request) {
    return req.user;
  }

  @Get('admin-only')
  @UseGuards(JwtAuthGuard, RolesGuard)
  @Roles('ADMIN')
  @HttpCode(HttpStatus.OK)
  getAdminArea() {
    return { message: 'Admin access granted.' };
  }
}
