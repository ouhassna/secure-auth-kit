const prisma = require("../src/config/db");

// Runs before each test file. Wipes auth-related tables so every test file
// starts from a clean slate, regardless of what previous files inserted.
beforeEach(async () => {
  await prisma.refreshToken.deleteMany();
  await prisma.user.deleteMany();
});

afterAll(async () => {
  await prisma.$disconnect();
});
