import { Test } from '@nestjs/testing';
import { ConfigService } from '@nestjs/config';
import { JwtService } from '@nestjs/jwt';
import { AuthService } from '../src/auth/auth.service';
import { PrismaService } from '../src/prisma/prisma.service';

const prismaMock = {
  user: {
    findUnique: jest.fn(),
    create: jest.fn(),
    update: jest.fn(),
  },
};

const jwtMock = {
  signAsync: jest.fn(),
  verifyAsync: jest.fn(),
};

const configMock = {
  get: jest.fn((key: string) => {
    if (key === 'JWT_ACCESS_SECRET') return 'access-secret';
    if (key === 'JWT_REFRESH_SECRET') return 'refresh-secret';
    return undefined;
  }),
};

describe('AuthService', () => {
  let service: AuthService;

  beforeEach(async () => {
    const moduleRef = await Test.createTestingModule({
      providers: [
        AuthService,
        { provide: PrismaService, useValue: prismaMock },
        { provide: JwtService, useValue: jwtMock },
        { provide: ConfigService, useValue: configMock },
      ],
    }).compile();

    service = moduleRef.get(AuthService);

    prismaMock.user.findUnique.mockReset();
    prismaMock.user.create.mockReset();
    prismaMock.user.update.mockReset();
    jwtMock.signAsync.mockReset();
    jwtMock.verifyAsync.mockReset();
  });

  it('registers a user and returns tokens', async () => {
    prismaMock.user.findUnique.mockResolvedValue(null);
    prismaMock.user.create.mockResolvedValue({
      id: 'user-1',
      email: 'test@example.com',
      role: 'TEAM_MEMBER',
    });
    prismaMock.user.update.mockResolvedValue({ id: 'user-1' });
    jwtMock.signAsync.mockResolvedValueOnce('access-token');
    jwtMock.signAsync.mockResolvedValueOnce('refresh-token');

    const tokens = await service.register({
      email: 'test@example.com',
      password: 'Password123',
    });

    expect(tokens).toEqual({
      accessToken: 'access-token',
      refreshToken: 'refresh-token',
    });
  });

  it('refreshes tokens when refresh token is valid', async () => {
    prismaMock.user.findUnique.mockResolvedValue({
      id: 'user-1',
      email: 'test@example.com',
      role: 'ADMIN',
      refreshTokenHash: await require('bcrypt').hash('refresh-token', 12),
      status: 'ACTIVE',
    });
    prismaMock.user.update.mockResolvedValue({ id: 'user-1' });
    jwtMock.signAsync.mockResolvedValueOnce('new-access-token');
    jwtMock.signAsync.mockResolvedValueOnce('new-refresh-token');

    const tokens = await service.refreshTokens('user-1', 'refresh-token');

    expect(tokens).toEqual({
      accessToken: 'new-access-token',
      refreshToken: 'new-refresh-token',
    });
  });
});
