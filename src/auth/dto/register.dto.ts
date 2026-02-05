import { IsEmail, IsEnum, IsOptional, IsString, MinLength } from 'class-validator';

export enum RegisterRole {
  ADMIN = 'ADMIN',
  OWNER = 'OWNER',
  TEAM_MEMBER = 'TEAM_MEMBER',
}

export class RegisterDto {
  @IsEmail()
  email: string;

  @IsString()
  @MinLength(8)
  password: string;

  @IsOptional()
  @IsEnum(RegisterRole)
  role?: RegisterRole;
}
