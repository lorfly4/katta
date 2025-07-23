module.exports = function authorize(allowedRoles = []) {
    return (req, res, next) => {
        const role = req.session.user?.role;
        if (!role || !allowedRoles.includes(role)) {
            return res.status(403).render('403', { title: 'Akses Ditolak', user: req.session.user });
        }
        next();
    };
};
