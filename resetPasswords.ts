import dotenv from 'dotenv';
import readline from 'readline';
import connection from './config/db'; // 引用现有的数据库连接配置
import { hashPassword } from './utils/password'; // 引用现有的 hashPassword 函数

// import .env variables
dotenv.config();

// 创建 readline 接口
const rl = readline.createInterface({
    input: process.stdin,
    output: process.stdout
});

// 提示用户选择操作
const promptUser = () => {
    rl.question('请选择操作: 1. 重置所有用户密码 2. 重置单个用户密码\n', (choice) => {
        if (choice === '1') {
            rl.question('你确定要重置所有用户的密码吗？此操作不可撤销。请输入 "yes" 确认: ', (confirm) => {
                if (confirm.toLowerCase() === 'yes') {
                    rl.question('请输入新密码: ', (newPassword) => {
                        resetAllPasswords(newPassword);
                    });
                } else {
                    console.log('操作已取消。');
                    rl.close();
                }
            });
        } else if (choice === '2') {
            rl.question('请输入用户的 UID 或 ID 或 username: ', (identifier) => {
                rl.question('请输入新密码: ', (newPassword) => {
                    resetSinglePassword(identifier, newPassword);
                });
            });
        } else {
            console.log('无效的选择。');
            rl.close();
        }
    });
};

// 重置所有用户的密码
const resetAllPasswords = async (newPassword: string) => {
    connection.connect(async (err) => {
        if (err) throw err;
        console.log('Connected to the database.');

        // 查询所有用户
        connection.query('SELECT id FROM users', async (error, results) => {
            if (error) throw error;

            // 将 results 转换为数组
            const users = results as any[];

            for (const user of users) {
                const hashedPassword = await hashPassword(newPassword);

                // 更新用户密码
                connection.query(
                    'UPDATE users SET password = ? WHERE id = ?',
                    [hashedPassword, user.id],
                    (updateError, updateResults) => {
                        if (updateError) throw updateError;
                        console.log(`Password updated for user ID: ${user.id}`);
                    }
                );
            }

            // 关闭数据库连接
            connection.end((endError) => {
                if (endError) throw endError;
                console.log('Database connection closed.');
                rl.close();
            });
        });
    });
};

// 重置单个用户的密码
const resetSinglePassword = async (identifier: string, newPassword: string) => {
    connection.connect(async (err) => {
        if (err) throw err;
        console.log('Connected to the database.');

        // 查询单个用户
        connection.query(
            'SELECT id FROM users WHERE id = ? OR uid = ? OR username = ?',
            [identifier, identifier, identifier],
            async (error, results) => {
                if (error) throw error;

                // 确保 results 是一个数组
                const users = results as any[];

                if (users.length === 0) {
                    console.log('User not found.');
                    rl.close();
                    return;
                }

                const user = users[0];
                const hashedPassword = await hashPassword(newPassword);

                // 更新用户密码
                connection.query(
                    'UPDATE users SET password = ? WHERE id = ?',
                    [hashedPassword, user.id],
                    (updateError, updateResults) => {
                        if (updateError) throw updateError;
                        console.log(`Password updated for user ID: ${user.id}`);
                    }
                );

                // 关闭数据库连接
                connection.end((endError) => {
                    if (endError) throw endError;
                    console.log('Database connection closed.');
                    rl.close();
                });
            }
        );
    });
};

// 开始提示用户
promptUser();
