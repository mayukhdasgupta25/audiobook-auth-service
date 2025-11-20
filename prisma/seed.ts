import { PrismaClient, Role } from '@prisma/client';
import argon2 from 'argon2';

// Prisma 7 reads connection from prisma.config.ts automatically
const prisma = new PrismaClient();

/**
 * Seed script to create initial users for development
 */
async function main() {
   console.log('🌱 Starting database seeding...');

   try {
      // Check if users already exist
      const existingUsers = await prisma.user.count();
      if (existingUsers > 0) {
         console.log('⚠️  Users already exist. Skipping seed.');
         return;
      }

      // Create normal user
      const normalUserPassword = await argon2.hash('user123', {
         type: argon2.argon2id,
         memoryCost: 65536,
         timeCost: 3,
         parallelism: 4,
      });

      const normalUser = await prisma.user.create({
         data: {
            email: 'user@example.com',
            password: normalUserPassword,
            role: Role.USER,
            emailVerified: true, // Pre-verified for development
         },
      });

      console.log('✅ Created normal user:', {
         id: normalUser.id,
         email: normalUser.email,
         role: normalUser.role,
      });

      // Create admin user
      const adminUserPassword = await argon2.hash('admin123', {
         type: argon2.argon2id,
         memoryCost: 65536,
         timeCost: 3,
         parallelism: 4,
      });

      const adminUser = await prisma.user.create({
         data: {
            email: 'admin@example.com',
            password: adminUserPassword,
            role: Role.ADMIN,
            emailVerified: true, // Pre-verified for development
         },
      });

      console.log('✅ Created admin user:', {
         id: adminUser.id,
         email: adminUser.email,
         role: adminUser.role,
      });

      console.log('\n🎉 Database seeding completed successfully!');
      console.log('\n📋 Test Credentials:');
      console.log('Normal User:');
      console.log('  Email: user@example.com');
      console.log('  Password: user123');
      console.log('\nAdmin User:');
      console.log('  Email: admin@example.com');
      console.log('  Password: admin123');
      console.log('\n💡 You can now test the authentication endpoints with these credentials.');

   } catch (error) {
      console.error('❌ Error during seeding:', error);
      throw error;
   }
}

main()
   .catch((e) => {
      console.error('❌ Seeding failed:', e);
      process.exit(1);
   })
   .finally(async () => {
      await prisma.$disconnect();
   });
