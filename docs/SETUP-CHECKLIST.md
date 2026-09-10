# Frozen V1 Setup Checklist

## Order

- [ ] Create GitHub repository
- [ ] Extract this ZIP
- [ ] Initialize Git
- [ ] Push to GitHub
- [ ] Create MongoDB Atlas project/cluster
- [ ] Create MongoDB database user
- [ ] Configure Atlas network access
- [ ] Obtain Atlas connection string
- [ ] Test backend locally against Atlas
- [ ] Connect GitHub repository to Render
- [ ] Deploy backend Web Service
- [ ] Add MONGODB_URI and CLIENT_ORIGIN in Render
- [ ] Verify backend health endpoint
- [ ] Deploy frontend Static Site
- [ ] Set VITE_API_BASE_URL to backend URL
- [ ] Update backend CLIENT_ORIGIN to frontend URL
- [ ] Verify frontend can reach backend

## Never commit

- MongoDB password
- MongoDB connection string containing credentials
- JWT secrets
- encryption keys
- plaintext Master Key
- plaintext FEKs
- plaintext ML-KEM private keys
