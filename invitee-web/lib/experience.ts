import sharedExperience from "../shared/HerdExperience.json";

type AuthenticationExperience = {
  brandName: string;
  releaseStatus: {
    label: string;
    heading: string;
    body: string;
    dismissButton: string;
  };
  welcome: {
    title: string;
    body: string;
    phoneLabel: string;
    phonePlaceholder: string;
    requestCodeButton: string;
    requestCodePendingButton: string;
  };
  verification: {
    navigationTitle: string;
    title: string;
    bodyPrefix: string;
    codeAccessibilityLabel: string;
    changePhoneAccessibilityLabel: string;
    verifyButton: string;
    verifyPendingButton: string;
    resendButton: string;
    resendPendingPrefix: string;
  };
  legal: {
    prefix: string;
    terms: string;
    privacy: string;
    suffix: string;
  };
  layout: {
    horizontalPadding: number;
    topPadding: number;
    welcomeTopSpacing: number;
    fieldHeight: number;
    buttonHeight: number;
    fieldCornerRadius: number;
    buttonCornerRadius: number;
    verificationCodeGap: number;
    verificationCodeWidth: number;
    verificationCodeHeight: number;
    verificationCodeCornerRadius: number;
    verificationCodeAlignment: string;
  };
};

type HomeExperience = {
  title: string;
  createEventTitle: string;
  invitesSectionTitle: string;
  hostedSectionTitle: string;
  unconfirmedSectionTitle: string;
  unconfirmedSectionNote: string;
  pastSectionTitle: string;
  emptyInvitesMessage: string;
  hostStatus: string;
  inviteeStatus: string;
  dateNotSet: string;
  untitledEvent: string;
  profile: {
    accessibilityLabel: string;
    useGenericIconWithoutName: boolean;
  };
  metrics: {
    invited: string;
    minimum: string;
    leftToRespond: string;
    noDeadline: string;
    responsesClosed: string;
  };
  layout: {
    horizontalPadding: number;
    topPadding: number;
    bottomPadding: number;
    verticalGap: number;
    headerToFirstCardGap: number;
    cardCornerRadius: number;
    cardPadding: number;
    createCardMinimumHeight: number;
    profileAvatarDiameter: number;
  };
  webCreateEventHandoff: {
    heading: string;
    body: string;
    backButton: string;
  };
};

type HerdExperience = {
  authentication: AuthenticationExperience;
  home: HomeExperience;
  profile: typeof sharedExperience.profile;
  invitation: typeof sharedExperience.invitation;
  attendees: typeof sharedExperience.attendees;
  reply: typeof sharedExperience.reply;
  privacy: typeof sharedExperience.privacy;
  success: typeof sharedExperience.success;
};

export const herdExperience = sharedExperience satisfies HerdExperience;
