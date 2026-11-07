import { defineConfig } from '@playwright/test';
export default defineConfig({testDir:'.',testMatch:['capacity-interaction.spec.ts'],workers:1,use:{baseURL:'http://127.0.0.1:5102',headless:true,channel:'msedge',trace:'off'},reporter:[['list']]});
