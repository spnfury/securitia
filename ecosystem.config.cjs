module.exports = {
  apps: [
    {
      name: "securitia",
      script: "server/index.js",
      cwd: "/home/admin/web/securitia.es/private/app",
      instances: 1,
      exec_mode: "fork",
      autorestart: true,
      max_memory_restart: "400M",
      env: { NODE_ENV: "production" },
      out_file: "/home/admin/web/securitia.es/logs/pm2-out.log",
      error_file: "/home/admin/web/securitia.es/logs/pm2-error.log",
      merge_logs: true,
      time: true,
    },
  ],
};
