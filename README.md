# A Test Github App

## Prerequisites

- Install Flask

```
pip install flask
```

- Install PyGithub

```
pip install PyGithub
```

- Install Waitress

```
pip install Waitress
```

## 1. Smee channel Creation

- Create a smee channel url on this website (https://smee.io)
- Click on "Start a new channel"
- Copy the created smee URL
- run the following command on your server
```
npm install smee
npx smee -u <your-smee-url>
```

## 2. Registering your Github Application

- On Github, go to Settings > Developer Settings > New Github App
- Fill in the following fields
```
Homepage URL: use the Smee.io channel (https://smee.io/CHANNEL-ID)

Webhook URL: use the Smee.io channel (https://smee.io/CHANNEL-ID)
```
- Generate a secret token (eg. using the following command) and copy it to the Webhook secret field
```
python3 -c 'import secrets; print(secrets.token_hex(64))'
```
- Edit the **Permission** as required by the app
- Edit the **Events** your app needs to subscribe to
- Click "Create Github App"

## 3. Installing your Github App

- Go to Settings > Developer Settings > Github Apps
- Click on "Edit" of the App you want to install
- Go to "Install App" tab on the right
- Click on "Install" to install the application on your account
- You can then select the repositories on whose the app should react to

## 4. Setting up the environment

- You will need to set up two environmental variables 
1. GITHUB_TOKEN
2. GITHUB_APP_SECRET_TOKEN

It can be set as such
```
export GITHUB_TOKEN=<your-github-token>
export GITHUB_APP_SECRET_TOKEN=<your-github-app-secret-token>
```

## 5. Starting up the flask app

- Run the following command to start up the flask app (in a separate instance from the smee channel)
```
npm install
chmod +x ./run_app.sh
./run_app/sh
```
