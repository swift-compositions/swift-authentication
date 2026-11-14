extension Authentication {

    /// Why a pending sign-in or a challenge is refused.
    public enum Error: Swift.Error, Sendable, Equatable {

        /// Its time is up.
        case expired

        /// Every attempt it allowed has been used.
        case exhausted

        /// The token presented is not the one issued.
        case token

        /// It is presented from another browser than the one that began it.
        case binding

        /// The second factor offered does not complete a sign-in.
        case factor(Factor)
    }
}
