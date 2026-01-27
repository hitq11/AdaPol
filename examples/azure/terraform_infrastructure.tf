# Azure Serverless E-commerce Order Processing Pipeline
terraform {
  required_providers {
    azurerm = {
      source  = "hashicorp/azurerm"
      version = "~> 3.0"
    }
  }
}

provider "azurerm" {
  features {}
}

# Resource Group
resource "azurerm_resource_group" "ecommerce" {
  name     = "ecommerce-rg"
  location = "East US"
}

# Storage Account for order data
resource "azurerm_storage_account" "order_data" {
  name                     = "orderdata${random_string.suffix.result}"
  resource_group_name      = azurerm_resource_group.ecommerce.name
  location                 = azurerm_resource_group.ecommerce.location
  account_tier             = "Standard"
  account_replication_type = "LRS"
}

resource "azurerm_storage_container" "orders" {
  name                  = "orders"
  storage_account_name  = azurerm_storage_account.order_data.name
  container_access_type = "private"
}

# Cosmos DB for order storage
resource "azurerm_cosmosdb_account" "orders" {
  name                = "orders-cosmosdb-${random_string.suffix.result}"
  location            = azurerm_resource_group.ecommerce.location
  resource_group_name = azurerm_resource_group.ecommerce.name
  offer_type          = "Standard"
  kind                = "GlobalDocumentDB"
  
  consistency_policy {
    consistency_level = "Session"
  }
  
  geo_location {
    location          = azurerm_resource_group.ecommerce.location
    failover_priority = 0
  }
}

resource "azurerm_cosmosdb_sql_database" "orders" {
  name                = "orders"
  resource_group_name = azurerm_resource_group.ecommerce.name
  account_name        = azurerm_cosmosdb_account.orders.name
}

# Function App
resource "azurerm_service_plan" "functions" {
  name                = "ecommerce-functions-plan"
  resource_group_name = azurerm_resource_group.ecommerce.name
  location            = azurerm_resource_group.ecommerce.location
  os_type             = "Linux"
  sku_name            = "Y1"
}

resource "azurerm_linux_function_app" "order_processor" {
  name                = "order-processor-${random_string.suffix.result}"
  resource_group_name = azurerm_resource_group.ecommerce.name
  location            = azurerm_resource_group.ecommerce.location
  
  storage_account_name       = azurerm_storage_account.order_data.name
  storage_account_access_key = azurerm_storage_account.order_data.primary_access_key
  service_plan_id           = azurerm_service_plan.functions.id
  
  site_config {
    application_stack {
      python_version = "3.11"
    }
  }
  
  app_settings = {
    STORAGE_ACCOUNT_NAME = azurerm_storage_account.order_data.name
    COSMOS_DB_ENDPOINT   = azurerm_cosmosdb_account.orders.endpoint
    COSMOS_DB_KEY        = azurerm_cosmosdb_account.orders.primary_key
  }
  
  identity {
    type = "SystemAssigned"
  }
}

resource "random_string" "suffix" {
  length  = 8
  special = false
  upper   = false
}
