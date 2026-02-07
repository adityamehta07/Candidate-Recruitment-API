import Map "mo:core/Map";
import Array "mo:core/Array";
import Runtime "mo:core/Runtime";
import Principal "mo:core/Principal";
import Iter "mo:core/Iter";
import Nat "mo:core/Nat";
import AccessControl "authorization/access-control";
import MixinAuthorization "authorization/MixinAuthorization";

actor {
  let accessControlState = AccessControl.initState();
  include MixinAuthorization(accessControlState);

  public type PipelineStage = {
    #applied;
    #screening;
    #interview;
    #hired;
    #rejected;
  };

  public type Candidate = {
    id : Nat;
    name : Text;
    email : Text;
    role : Text;
    resume : Text;
    stage : PipelineStage;
    owner : Principal;
  };

  public type CandidateInput = {
    name : Text;
    email : Text;
    role : Text;
    resume : Text;
  };

  public type CandidateUpdate = {
    name : Text;
    email : Text;
    role : Text;
    resume : Text;
  };

  public type UserProfile = {
    name : Text;
  };

  let candidates = Map.empty<Nat, Candidate>();
  var nextCandidateId = 0;
  let ownerToCandidateId = Map.empty<Principal, Nat>();
  let userProfiles = Map.empty<Principal, UserProfile>();

  module PipelineStage {
    public func compare(stage1 : PipelineStage, stage2 : PipelineStage) : {
      #less;
      #equal;
      #greater;
    } {
      let getStagePosition = func(stage : PipelineStage) : Nat {
        switch (stage) {
          case (#applied) { 0 };
          case (#screening) { 1 };
          case (#interview) { 2 };
          case (#hired) { 3 };
          case (#rejected) { 4 };
        };
      };

      let pos1 = getStagePosition(stage1);
      let pos2 = getStagePosition(stage2);

      if (pos1 < pos2) { #less } else if (pos1 == pos2) {
        #equal;
      } else { #greater };
    };
  };

  // Ensures the caller has at least `user` access
  // Can be called by anyone. Admin rights cannot be granted this way.
  public shared ({ caller }) func ensureUserAccess() : async () {
    switch (AccessControl.getUserRole(accessControlState, caller)) {
      case (#guest) {
        AccessControl.assignRole(
          accessControlState,
          caller,
          caller,
          #user,
        );
      };
      case (_) { () };
    };
  };

  // User Profile Functions
  public query ({ caller }) func getCallerUserProfile() : async ?UserProfile {
    if (not (AccessControl.hasPermission(accessControlState, caller, #user))) {
      Runtime.trap("Unauthorized: Only users can view profiles");
    };
    userProfiles.get(caller);
  };

  public query ({ caller }) func getUserProfile(user : Principal) : async ?UserProfile {
    if (caller != user and not AccessControl.isAdmin(accessControlState, caller)) {
      Runtime.trap("Unauthorized: Can only view your own profile");
    };
    userProfiles.get(user);
  };

  public shared ({ caller }) func saveCallerUserProfile(profile : UserProfile) : async () {
    if (not AccessControl.hasPermission(accessControlState, caller, #user)) {
      Runtime.trap("Unauthorized: Only users can save profiles");
    };
    userProfiles.add(caller, profile);
  };

  // Create or Update Candidate for Current Principal (Single Application Per User)
  public shared ({ caller }) func upsertCandidate(input : CandidateInput) : async Nat {
    if (not AccessControl.hasPermission(accessControlState, caller, #user)) {
      Runtime.trap("Unauthorized: Only candidates can add candidate records");
    };

    switch (ownerToCandidateId.get(caller)) {
      case (null) {
        // New candidate
        let candidateId = nextCandidateId;
        let candidate = {
          id = candidateId;
          name = input.name;
          email = input.email;
          role = input.role;
          resume = input.resume;
          stage = #applied;
          owner = caller;
        };

        candidates.add(candidateId, candidate);
        ownerToCandidateId.add(caller, candidateId);
        nextCandidateId += 1;
        candidateId;
      };
      case (?existingCandidateId) {
        // Update existing candidate
        let existingCandidate = candidates.get(existingCandidateId);
        switch (existingCandidate) {
          case (null) {
            // Clean up inconsistent state (should not happen)
            ownerToCandidateId.remove(caller);
            Runtime.trap("Data inconsistency found. Your application record was missing and has been reset. Please try again.");
          };
          case (?c) {
            let updatedCandidate = {
              c with
              name = input.name;
              email = input.email;
              role = input.role;
              resume = input.resume;
            };
            candidates.add(existingCandidateId, updatedCandidate);
            existingCandidateId;
          };
        };
      };
    };
  };

  // UPDATE: Update only allowed for existing records (to retain resume pipeline stages)
  public shared ({ caller }) func updateCandidate(input : CandidateUpdate) : async () {
    if (not AccessControl.hasPermission(accessControlState, caller, #user)) {
      Runtime.trap("Unauthorized: Only candidates can update candidate records");
    };

    switch (ownerToCandidateId.get(caller)) {
      case (null) { Runtime.trap("Candidate record not found. Use upsertCandidate to create a new record") };
      case (?candidateId) {
        switch (candidates.get(candidateId)) {
          case (null) {
            // Clean up inconsistent state (should not happen)
            ownerToCandidateId.remove(caller);
            Runtime.trap("Data inconsistency found. Your application record was missing and has been reset. Please try again.");
          };
          case (?candidate) {
            let updatedCandidate = {
              candidate with
              name = input.name;
              email = input.email;
              role = input.role;
              resume = input.resume;
            };
            candidates.add(candidateId, updatedCandidate);
          };
        };
      };
    };
  };

  // Candidates can view only their candidate record
  public query ({ caller }) func getMyCandidate() : async ?Candidate {
    if (not AccessControl.hasPermission(accessControlState, caller, #user)) {
      Runtime.trap("Unauthorized: Only candidates can view candidate records");
    };

    switch (ownerToCandidateId.get(caller)) {
      case (null) { null };
      case (?candidateId) { candidates.get(candidateId) };
    };
  };

  // Recruiters (admins) can view all candidates
  public query ({ caller }) func getAllCandidates() : async [Candidate] {
    if (not AccessControl.isAdmin(accessControlState, caller)) {
      Runtime.trap("Unauthorized: Only recruiters can view all candidates");
    };
    candidates.values().toArray();
  };

  // Recruiters (admins) can update candidate stage
  public shared ({ caller }) func updateCandidateStage(candidateId : Nat, newStage : PipelineStage) : async () {
    if (not AccessControl.isAdmin(accessControlState, caller)) {
      Runtime.trap("Unauthorized: Only recruiters can advance candidates through the pipeline");
    };

    switch (candidates.get(candidateId)) {
      case (null) { Runtime.trap("Candidate not found") };
      case (?candidate) {
        validateStageTransition(candidate.stage, newStage);
        let updatedCandidate = {
          candidate with stage = newStage;
        };
        candidates.add(candidateId, updatedCandidate);
      };
    };
  };

  // Candidates can delete their candidate record
  public shared ({ caller }) func deleteCandidate() : async () {
    if (not AccessControl.hasPermission(accessControlState, caller, #user)) {
      Runtime.trap("Unauthorized: Only candidates can delete candidate records");
    };

    switch (ownerToCandidateId.get(caller)) {
      case (null) { Runtime.trap("Candidate record not found") };
      case (?candidateId) {
        candidates.remove(candidateId);
        ownerToCandidateId.remove(caller);
      };
    };
  };

  // Recruiters can view all candidates by stage
  public query ({ caller }) func getCandidatesByStage(stage : PipelineStage) : async [Candidate] {
    if (not AccessControl.isAdmin(accessControlState, caller)) {
      Runtime.trap("Unauthorized: Only recruiters can view candidates by stage");
    };

    candidates.values().toArray().filter(
      func(candidate) {
        candidate.stage == stage;
      }
    );
  };

  // Stage transition validation logic
  func validateStageTransition(current : PipelineStage, next : PipelineStage) {
    switch (current) {
      case (#hired) { Runtime.trap("Invalid transition: Candidate is already hired") };
      case (#rejected) { Runtime.trap("Invalid transition: Candidate has been rejected") };
      case (_) {
        if (next == current) { Runtime.trap("Invalid transition: No change needed") };
      };
    };
  };
};
